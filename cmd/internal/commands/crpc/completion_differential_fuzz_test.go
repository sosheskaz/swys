package crpc_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sosheskaz/swys/cmd"
	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

const (
	crpcFuzzMaxElements   = 8
	crpcFuzzMaxCandidates = 3
	// crpcFuzzRunTimeout only bounds a hung run; local fixtures answer at once.
	crpcFuzzRunTimeout = 20 * time.Second
	// crpcFuzzSlowCompletion is half of completion's own cap.
	crpcFuzzSlowCompletion = time.Second
	crpcFuzzService        = "example.v1.EchoService"
	crpcFuzzMethod         = crpcFuzzService + "/Echo"
)

// Each input byte selects through a fixed modulus larger than its list, and an
// input naming an unassigned code is skipped, so appending entries never
// reinterprets a recorded input.
const (
	crpcFuzzTargetCodes  = 8
	crpcFuzzSlotCodes    = 16
	crpcFuzzPrefixCodes  = 8
	crpcFuzzElementCodes = 128
)

func crpcFuzzPick[T any](values []T, choice byte, codes int) (T, bool) {
	var zero T
	if index := int(choice) % codes; index < len(values) {
		return values[index], true
	}
	return zero, false
}

// crpcFuzzStdinFlags read original stdin when their value is an exact dash.
var crpcFuzzStdinFlags = []string{"ca", "cert", "key", "auth-bearer-file", "auth-basic-file"}

// crpcFuzzTargets are the URL argument: base and procedure URLs for both
// fixtures, none for offline discovery, and an unparseable one.
var crpcFuzzTargets = []string{"{plain}", "{tls}", "{plain}" + echoMethod, "{tls}" + echoMethod, "", "not a URL"}

// crpcFuzzElement is one argument group the fuzzer places on a command line.
// Append new elements only: checked-in corpora select elements by index.
type crpcFuzzElement struct {
	// changes maps each flag the group sets to whether its value is stdin.
	changes    map[string]bool
	name       string
	args       []string
	positional bool
}

func crpcFuzzFlag(name string, args []string, flags ...string) crpcFuzzElement {
	changes := make(map[string]bool, len(flags))
	for _, flag := range flags {
		changes[flag] = args[len(args)-1] == "-" || strings.HasSuffix(args[len(args)-1], "=-")
	}
	return crpcFuzzElement{name: name, args: args, changes: changes}
}

var crpcFuzzElements = []crpcFuzzElement{
	crpcFuzzFlag("protoset", []string{"--protoset", "{protoset}"}, "protoset"),
	crpcFuzzFlag("protoset-streaming", []string{"--protoset", "{streaming-protoset}"}, "protoset"),
	crpcFuzzFlag("protoset-missing", []string{"--protoset", "{missing}"}, "protoset"),
	crpcFuzzFlag("protoset-directory", []string{"--protoset", "{dir}"}, "protoset"),
	crpcFuzzFlag("protoset-empty", []string{"--protoset="}, "protoset"),
	crpcFuzzFlag("reflect", []string{"--reflect"}, "reflect"),
	crpcFuzzFlag("reflection-timeout-negative", []string{"--reflection-timeout=-1s"}, "reflection-timeout"),
	{name: "method", args: []string{crpcFuzzMethod}, positional: true},
	{name: "method-missing", args: []string{crpcFuzzService + "/Missing"}, positional: true},
	{name: "method-invalid", args: []string{"noslash"}, positional: true},
	crpcFuzzFlag("list", []string{"--list", crpcFuzzService}, "list"),
	crpcFuzzFlag("list-empty", []string{"--list="}, "list"),
	crpcFuzzFlag("describe", []string{"--describe", "example.v1.Request"}, "describe"),
	crpcFuzzFlag("describe-empty", []string{"--describe="}, "describe"),
	crpcFuzzFlag("template", []string{"--template", crpcFuzzMethod}, "template"),
	crpcFuzzFlag("template-empty", []string{"--template="}, "template"),
	crpcFuzzFlag("data", []string{"-d", "{}"}, "data"),
	crpcFuzzFlag("input", []string{"-i", "{request}"}, "input"),
	crpcFuzzFlag("input-stdin", []string{"-i", "-"}, "input"),
	crpcFuzzFlag("stdin-always", []string{"--stdin", "always"}, "stdin"),
	crpcFuzzFlag("stdin-never", []string{"--stdin=never"}, "stdin"),
	crpcFuzzFlag("stdin-invalid", []string{"--stdin", "sometimes"}, "stdin"),
	crpcFuzzFlag("stream-unary", []string{"--stream", "unary"}, "stream"),
	crpcFuzzFlag("stream-server", []string{"--stream", "server"}, "stream"),
	crpcFuzzFlag("stream-bidi", []string{"--stream=bidi"}, "stream"),
	crpcFuzzFlag("stream-invalid", []string{"--stream", "sideways"}, "stream"),
	crpcFuzzFlag("wait", []string{"-w", "5s"}, "wait"),
	crpcFuzzFlag("header", []string{"-H", "x-fuzz: 1"}, "header"),
	crpcFuzzFlag("header-invalid", []string{"-H", "bad header"}, "header"),
	crpcFuzzFlag("header-authorization", []string{"-H", "authorization: Bearer header-token"}, "header"),
	crpcFuzzFlag("header-reserved", []string{"-H", "content-type: text/plain"}, "header"),
	crpcFuzzFlag("connect-timeout-negative", []string{"--connect-timeout=-1s"}, "connect-timeout"),
	crpcFuzzFlag("timeout-negative", []string{"--timeout=-1s"}, "timeout"),
	crpcFuzzFlag("max-message-size-zero", []string{"--max-message-size", "0"}, "max-message-size"),
	crpcFuzzFlag("ca", []string{"--ca", "{ca}"}, "ca"),
	crpcFuzzFlag("ca-stdin", []string{"--ca", "-"}, "ca"),
	crpcFuzzFlag("ca-missing", []string{"--ca", "{missing}"}, "ca"),
	crpcFuzzFlag("system-ca", []string{"--system-ca"}, "system-ca"),
	crpcFuzzFlag("insecure", []string{"--insecure"}, "insecure"),
	crpcFuzzFlag("insecure-no-verify", []string{"--insecure-no-verify"}, "insecure-no-verify"),
	crpcFuzzFlag("servername", []string{"--servername", "localhost"}, "servername"),
	crpcFuzzFlag("cert", []string{"--cert", "{cert}"}, "cert"),
	crpcFuzzFlag("key", []string{"-k", "{key}"}, "key"),
	crpcFuzzFlag("cert-stdin", []string{"--cert", "-"}, "cert"),
	crpcFuzzFlag("key-stdin", []string{"--key=-"}, "key"),
	crpcFuzzFlag("bearer", []string{"--auth-bearer", "token"}, "auth-bearer"),
	crpcFuzzFlag("bearer-file", []string{"--auth-bearer-file", "{token}"}, "auth-bearer-file"),
	crpcFuzzFlag("bearer-file-stdin", []string{"--auth-bearer-file", "-"}, "auth-bearer-file"),
	crpcFuzzFlag("basic", []string{"--auth-basic", "user:pass"}, "auth-basic"),
	crpcFuzzFlag("basic-file", []string{"--auth-basic-file", "{basic}"}, "auth-basic-file"),
	crpcFuzzFlag("basic-file-stdin", []string{"--auth-basic-file=-"}, "auth-basic-file"),
	crpcFuzzFlag("cleartext-auth", []string{"--insecure-cleartext-auth"}, "insecure-cleartext-auth"),
	crpcFuzzFlag("output", []string{"-o", "{out}"}, "output"),
	crpcFuzzFlag("output-protoset", []string{"-o", "{protoset}"}, "output"),
	crpcFuzzFlag("format-json", []string{"-f", "json"}, "format"),
	crpcFuzzFlag("format-jsonl", []string{"--format", "jsonl"}, "format"),
	crpcFuzzFlag("format-text", []string{"--format", "text"}, "format"),
	crpcFuzzFlag("format-invalid", []string{"--format", "yaml"}, "format"),
	crpcFuzzFlag("verbose", []string{"-v"}, "verbose"),
	crpcFuzzFlag("encoding-invalid", []string{"-e", "bogus"}, "encoding"),
	crpcFuzzFlag("input-encoding-invalid", []string{"--input-encoding", "bogus"}, "input-encoding"),
	crpcFuzzFlag("ca-encoding-base64", []string{"--ca-encoding", "base64"}, "ca-encoding"),
	crpcFuzzFlag("mode", []string{"--mode", "0600"}, "mode"),
	crpcFuzzFlag("mode-invalid", []string{"--mode=rwx"}, "mode"),
	crpcFuzzFlag("input-missing", []string{"-i", "{missing}"}, "input"),
	crpcFuzzFlag("bearer-empty", []string{"--auth-bearer="}, "auth-bearer"),
	crpcFuzzFlag("basic-invalid", []string{"--auth-basic", "nocolon"}, "auth-basic"),
	crpcFuzzFlag("input-encoding-base64", []string{"--input-encoding", "base64"}, "input-encoding"),
	crpcFuzzFlag("data-base64", []string{"-d", "e30="}, "data"),
}

// crpcFuzzSlot is the word being completed. An empty flag completes the method.
type crpcFuzzSlot struct {
	name string
	flag string
	// fill is a valid value used to execute the line when completion offered none.
	fill     string
	prefixes []string
	// invocation adds a request body to executions, as the user would supply one.
	invocation bool
	// static candidates are fixed words rather than schema-derived ones.
	static bool
	// data slots complete the request body, in any spelling of -d.
	data bool
	// joined slots type the value in the flag's own word, as in --data=VALUE.
	joined bool
}

var crpcFuzzSlots = []crpcFuzzSlot{
	{
		name: "method", prefixes: []string{"", "example.", crpcFuzzService + "/", crpcFuzzService + "/E", "zz"},
		fill: crpcFuzzMethod, invocation: true,
	},
	{name: "list", flag: "--list", prefixes: []string{"", "example.", "zz"}, fill: crpcFuzzService},
	{
		// Completion reflects lazily, listing services before their files, so the
		// fill is a symbol reachable from every prefix it extends.
		name: "describe", flag: "--describe", fill: crpcFuzzService,
		prefixes: []string{"", "example.v1.", crpcFuzzService + ".", "example.v1.Request", "zz"},
	},
	{name: "template", flag: "--template", prefixes: []string{"", "example.", crpcFuzzService + "/", "zz"}, fill: crpcFuzzMethod},
	{name: "data", flag: "--data", prefixes: crpcFuzzDataPrefixes, fill: "{}", data: true},
	{name: "stream", flag: "--stream", prefixes: []string{"", "u", "s", "zz"}, fill: "unary", invocation: true, static: true},
	{name: "format", flag: "--format", prefixes: []string{"", "j", "t"}, fill: "json", static: true},
	{name: "flag-name", prefixes: []string{"-", "--", "--s", "--auth-"}, fill: crpcFuzzMethod, invocation: true, static: true},
	{name: "data-short", flag: "-d", prefixes: crpcFuzzDataPrefixes, fill: "{}", data: true},
	{name: "data-inline", flag: "--data=", prefixes: crpcFuzzDataPrefixes, fill: "{}", data: true, joined: true},
	// -v is boolean, so pflag gives the cluster's value to -d.
	{name: "data-cluster", flag: "-vd", prefixes: crpcFuzzDataPrefixes, fill: "{}", data: true},
	{name: "data-cluster-inline", flag: "-vd=", prefixes: crpcFuzzDataPrefixes, fill: "{}", data: true, joined: true},
	{name: "list-inline", flag: "--list=", prefixes: []string{"", "example.", "zz"}, fill: crpcFuzzService, joined: true},
}

var crpcFuzzDataPrefixes = []string{"", "{", `'{"`, `"{"`, "zz"}

// FuzzCRPCCompletionStaysWithinExecution checks completion against the command
// line it completes: completion must never call a method, read stdin, or create
// output; must follow the documented -d quiet rules; and may contact the server
// or offer a schema-derived candidate only when execution would accept the same
// line rather than reject it before any network use.
func FuzzCRPCCompletionStaysWithinExecution(f *testing.F) {
	for _, slot := range crpcFuzzSlots {
		if len(slot.prefixes) > crpcFuzzPrefixCodes {
			f.Fatalf("slot %s outgrew its prefix codes", slot.name)
		}
	}
	if len(crpcFuzzTargets) > crpcFuzzTargetCodes || len(crpcFuzzSlots) > crpcFuzzSlotCodes || len(crpcFuzzElements) > crpcFuzzElementCodes {
		f.Fatal("a fuzz vocabulary outgrew its codes")
	}
	// Only the client certificate and key are used; servers present their own leaf.
	identity := testcmd.CreateNetworkIdentity(f, cmd.NewCommand)
	add := func(target uint8, slot string, prefix uint8, elements ...string) {
		f.Add(target, crpcFuzzSlotIndex(f, slot), prefix, crpcFuzzElementIndexes(f, elements...))
	}
	add(0, "method", 2, "cleartext-auth", "bearer")
	add(1, "method", 2, "ca")
	add(1, "describe", 2, "ca", "bearer")
	add(4, "list", 0, "protoset")
	add(0, "template", 2, "header")
	add(2, "data", 0, "protoset")
	add(0, "data", 0, "method")
	add(2, "stream", 0, "protoset-streaming")
	// Typed -d completion once reflected with credentials beside an empty discovery flag.
	add(2, "data", 0, "cleartext-auth", "bearer", "list-empty")
	add(2, "data", 0, "protoset", "template-empty")
	// A stdin credential once failed to silence -d completion from a protoset.
	add(3, "data", 0, "protoset", "bearer-file-stdin")
	add(3, "data", 0, "protoset", "ca-stdin")
	add(3, "data", 0, "protoset", "bearer", "basic-file-stdin")
	// An offline SERVICE/ prefix is checked through the fill that completes it.
	add(0, "method", 0, "protoset", "format-invalid")
	add(2, "data-cluster", 0, "protoset")
	add(2, "data-cluster-inline", 1, "protoset")
	// A supplied --ca follows --ca-encoding; completion never reads TLS contents.
	add(1, "list", 0, "protoset", "ca", "ca-encoding-base64")

	f.Fuzz(func(t *testing.T, targetChoice, slotChoice, prefixChoice uint8, choices []byte) {
		line, prefix, ok := decodeCRPCFuzzLine(targetChoice, slotChoice, prefixChoice, choices)
		if !ok {
			t.Skip("input names an unassigned code or a positional word without a URL")
		}
		line.env = newCRPCFuzzEnvironment(t, &identity)
		if violation := line.check(t, prefix); violation != nil {
			t.Fatalf("%s: %s", violation.rule, violation.detail)
		}
	})
}

func decodeCRPCFuzzLine(targetChoice, slotChoice, prefixChoice uint8, choices []byte) (*crpcFuzzLine, string, bool) {
	target, targetOK := crpcFuzzPick(crpcFuzzTargets, targetChoice, crpcFuzzTargetCodes)
	slot, slotOK := crpcFuzzPick(crpcFuzzSlots, slotChoice, crpcFuzzSlotCodes)
	prefix, prefixOK := crpcFuzzPick(slot.prefixes, prefixChoice, crpcFuzzPrefixCodes)
	line := &crpcFuzzLine{target: target, slot: slot}
	// Without a URL a positional word would become the target and name a remote host.
	positional := target == "" && slot.flag == ""
	for _, choice := range choices[:min(len(choices), crpcFuzzMaxElements)] {
		element, ok := crpcFuzzPick(crpcFuzzElements, choice, crpcFuzzElementCodes)
		if !ok {
			return nil, "", false
		}
		positional = positional || target == "" && element.positional
		line.elements = append(line.elements, element)
	}
	return line, prefix, targetOK && slotOK && prefixOK && !positional
}

type crpcFuzzLine struct {
	env *crpcFuzzEnvironment
	// target is the URL argument; empty omits it for offline discovery.
	target   string
	elements []crpcFuzzElement
	slot     crpcFuzzSlot
}

// crpcFuzzViolation names a broken contract; rule groups equivalent findings.
type crpcFuzzViolation struct {
	rule, detail string
}

func (line *crpcFuzzLine) check(t *testing.T, prefix string) *crpcFuzzViolation {
	t.Helper()
	completionArgs := line.withSlot(prefix)
	stdin := &crpcFuzzCountingReader{}
	protoset := line.env.protoset(t)
	before := line.env.traffic()
	started := time.Now()
	output, err := line.env.run(t, stdin, append([]string{"__complete", "crpc"}, completionArgs...)...)
	elapsed := time.Since(started)
	completion := line.env.traffic().since(before)
	if err != nil {
		return &crpcFuzzViolation{rule: "completion failed", detail: fmt.Sprintf("complete %q: %v", completionArgs, err)}
	}
	finals, partials := crpcFuzzCandidates(t, output)
	report := func(rule, detail string) *crpcFuzzViolation {
		return &crpcFuzzViolation{rule: rule, detail: fmt.Sprintf(
			"completing %q: %s\ncompletion output: %q\ncompletion traffic: %+v", completionArgs, detail, output, completion,
		)}
	}

	if completion.calls != 0 {
		return report("method invoked", "completion invoked an application method")
	}
	if reads := stdin.reads.Load(); reads != 0 {
		return report("stdin read", fmt.Sprintf("completion read stdin %d times", reads))
	}
	switch line.lastChange("output") {
	case "output":
		if _, err := os.Stat(line.env.outPath); !errors.Is(err, os.ErrNotExist) {
			return report("output created", fmt.Sprintf("completion created its output file: %v", err))
		}
	case "output-protoset":
		if !bytes.Equal(protoset, line.env.protoset(t)) {
			return report("output written", "completion changed the existing file named by -o")
		}
	}
	stdinArtifact := line.stdinArtifact()
	if stdinArtifact && completion.network() {
		return report("stdin artifact contacted", "completion contacted the server while a TLS or credential file is stdin")
	}
	if line.slot.data && len(finals) != 0 {
		switch {
		case stdinArtifact:
			return report("stdin artifact template", "-d offered a template while a TLS or credential file is stdin")
		case line.changed("input"):
			return report("input template", "-d offered a template beside --input")
		case line.changed("list") || line.changed("describe") || line.changed("template"):
			return report("discovery template", "-d offered a template beside a discovery flag")
		}
	}
	if stdinArtifact {
		// Execution would read the stdin artifact; the rules above cover this line.
		return nil
	}
	// A partial SERVICE/ word is checked through the fill, which completes it.
	offered := !line.slot.static && (len(partials) != 0 || len(finals) != 0)
	// Completion stops at its own two-second cap and then offers nothing by design;
	// only a loaded machine gets near it, as local fixtures answer in milliseconds.
	expected := line.expectsCompletion(prefix) && elapsed < crpcFuzzSlowCompletion
	var fillRun crpcFuzzRun
	if completion.network() || offered || expected {
		fillRun = line.execute(t, line.fill())
		switch {
		case fillRun.rejected() && completion.network():
			return report("contacted for rejected line", "completion contacted the server for a line execution rejects first: "+fillRun.String())
		case fillRun.rejected() && offered:
			return report("offered for rejected line", "completion offered a word for a line execution rejects first: "+fillRun.String())
		}
	}
	if line.slot.static {
		return nil
	}
	executed := false
	for _, candidate := range crpcFuzzSample(finals) {
		run := line.execute(t, candidate)
		if run.rejected() {
			return report("offered for rejected line", fmt.Sprintf("completion offered %q for a line execution rejects first: %s", candidate, run))
		}
		executed = executed || run.err == nil
	}
	if expected && fillRun.err == nil && !line.offers(finals, partials, executed) {
		return report("missing completion", "completion offered no working word for a line execution accepts: "+fillRun.String())
	}
	return nil
}

// fill is the slot's valid value, with request bodies in the line's encoding.
func (line *crpcFuzzLine) fill() string {
	if line.slot.data {
		return line.body()
	}
	return line.slot.fill
}

// expectsCompletion reports whether a successful execution with the fill obliges
// completion to offer it: the fill must extend the typed prefix and no documented
// quiet rule may apply. Lines with a stdin TLS or credential file never get here.
func (line *crpcFuzzLine) expectsCompletion(prefix string) bool {
	switch {
	case line.slot.static:
		return false
	case line.slot.data:
		// The template is compact JSON for a message with fields, so it starts
		// with {" whatever quote the shell word opens with. Under another
		// --input-encoding JSON is not a valid body, so no template is owed.
		return slices.Contains([]string{"", "{", `{"`}, strings.TrimLeft(prefix, `'"`)) && line.body() == "{}" &&
			!line.changed("input") && !line.changed("list") && !line.changed("describe") && !line.changed("template")
	default:
		return strings.HasPrefix(line.slot.fill, prefix)
	}
}

// offers reports whether completion offered the fill or, for -d, a template;
// executed reports whether an offered final word ran successfully, so a stray
// word cannot pass for a request template.
func (line *crpcFuzzLine) offers(finals, partials []string, executed bool) bool {
	if line.slot.data {
		return executed
	}
	return slices.Contains(finals, line.slot.fill) ||
		slices.ContainsFunc(partials, func(partial string) bool { return strings.HasPrefix(line.slot.fill, partial) })
}

// withSlot returns the line's arguments with value typed in the completed slot.
func (line *crpcFuzzLine) withSlot(value string) []string {
	switch {
	case line.slot.joined:
		return append(line.args(), line.slot.flag+value)
	case line.slot.flag != "":
		return append(line.args(), line.slot.flag, value)
	default:
		return append(line.args(), value)
	}
}

// crpcFuzzRun is one execution of the line with a value in the completed slot.
type crpcFuzzRun struct {
	err     error
	args    []string
	traffic crpcFuzzTraffic
}

// rejected reports a failure before either fixture was reached.
func (run crpcFuzzRun) rejected() bool { return run.err != nil && !run.traffic.network() }

func (run crpcFuzzRun) String() string {
	result := "ok"
	if run.err != nil {
		result = run.err.Error()
	}
	return "crpc " + strings.Join(run.args, " ") + ": " + result
}

func (line *crpcFuzzLine) execute(t *testing.T, value string) crpcFuzzRun {
	t.Helper()
	args := line.withSlot(value)
	if line.slot.invocation && !line.changed("data") && !line.changed("input") && !line.changed("stdin") {
		args = append(args, "--data", line.body())
	}
	before := line.env.traffic()
	_, err := line.env.run(t, strings.NewReader(line.body()), append([]string{"crpc"}, args...)...)
	return crpcFuzzRun{err: err, args: args, traffic: line.env.traffic().since(before)}
}

func (line *crpcFuzzLine) args() []string {
	var args []string
	if line.target != "" {
		args = append(args, line.env.expand(line.target))
	}
	for _, element := range line.elements {
		for _, arg := range element.args {
			// Supplied requests and TLS files follow the line's encodings, so
			// their contents never cause a rejection; completion deliberately
			// does not read them.
			switch {
			case arg == "{request}" && line.body() != "{}":
				arg = "{request-base64}"
			case arg == "{ca}" && line.lastChange("ca-encoding") == "ca-encoding-base64":
				arg = "{ca-base64}"
			}
			args = append(args, line.env.expand(arg))
		}
	}
	return args
}

// body is an empty request in the line's last --input-encoding, which execution
// decodes from every request source. It supplies the harness's own requests;
// literal -d elements stay as typed, so a mismatch is an invalid typed line.
func (line *crpcFuzzLine) body() string {
	if line.lastChange("input-encoding") == "input-encoding-base64" {
		return "e30="
	}
	return "{}"
}

// lastChange names the last element that set flag, following pflag's
// last-value-wins rule, or returns "" when none did.
func (line *crpcFuzzLine) lastChange(flag string) string {
	name := ""
	for _, element := range line.elements {
		if _, ok := element.changes[flag]; ok {
			name = element.name
		}
	}
	return name
}

func (line *crpcFuzzLine) changed(flag string) bool {
	for _, element := range line.elements {
		if _, ok := element.changes[flag]; ok {
			return true
		}
	}
	return false
}

// stdinArtifact applies pflag's last-value-wins rule to each stdin-capable flag.
func (line *crpcFuzzLine) stdinArtifact() bool {
	for _, flag := range crpcFuzzStdinFlags {
		stdin := false
		for _, element := range line.elements {
			if value, ok := element.changes[flag]; ok {
				stdin = value
			}
		}
		if stdin {
			return true
		}
	}
	return false
}

// crpcFuzzCandidates returns the final words completion offered and its partial
// words, whose trailing slash continues to a method.
func crpcFuzzCandidates(t *testing.T, output string) ([]string, []string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[len(lines)-1], ":") {
		t.Fatalf("completion output = %q, want a directive", output)
	}
	var finals, partials []string
	for _, line := range lines[:len(lines)-1] {
		candidate, _, _ := strings.Cut(line, "\t")
		switch {
		case strings.HasSuffix(candidate, "/"):
			partials = append(partials, candidate)
		case candidate != "":
			finals = append(finals, candidate)
		}
	}
	return finals, partials
}

func crpcFuzzSample(candidates []string) []string {
	if len(candidates) <= crpcFuzzMaxCandidates {
		return candidates
	}
	return []string{candidates[0], candidates[len(candidates)/2], candidates[len(candidates)-1]}
}

type crpcFuzzCountingReader struct{ reads atomic.Int64 }

func (reader *crpcFuzzCountingReader) Read([]byte) (int, error) {
	reader.reads.Add(1)
	return 0, io.EOF
}

type crpcFuzzEnvironment struct {
	paths   map[string]string
	outPath string
	servers []*crpcFuzzServer
}

func newCRPCFuzzEnvironment(t *testing.T, identity *testcmd.NetworkIdentity) *crpcFuzzEnvironment {
	t.Helper()
	plain := startCRPCFuzzServer(t, false)
	secure := startCRPCFuzzServer(t, true)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: secure.Certificate().Raw})
	directory := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return path
	}
	env := &crpcFuzzEnvironment{
		servers: []*crpcFuzzServer{plain, secure},
		outPath: filepath.Join(directory, "out.json"),
	}
	env.paths = map[string]string{
		"{plain}":              plain.URL,
		"{tls}":                secure.URL,
		"{protoset}":           writeProtoset(t, schemaSet(false)),
		"{streaming-protoset}": writeProtoset(t, schemaSet(true)),
		"{request}":            write("request.json", "{}"),
		"{request-base64}":     write("request.b64", "e30="),
		"{token}":              write("token", "token\n"),
		"{basic}":              write("basic", "user:pass\n"),
		// httptest's leaf names 127.0.0.1, so --ca with it alone verifies the fixture.
		"{ca}":        write("fixture-ca.pem", string(caPEM)),
		"{ca-base64}": write("fixture-ca.b64", base64.StdEncoding.EncodeToString(caPEM)),
		"{cert}":      identity.ClientCert,
		"{key}":       identity.ClientKey,
		"{dir}":       directory,
		"{missing}":   filepath.Join(directory, "missing"),
		"{out}":       env.outPath,
	}
	return env
}

// protoset returns the fixture protoset's bytes, which -o may name.
func (env *crpcFuzzEnvironment) protoset(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(env.paths["{protoset}"])
	if err != nil {
		t.Fatalf("read fixture protoset: %v", err)
	}
	return data
}

func (env *crpcFuzzEnvironment) expand(arg string) string {
	for placeholder, path := range env.paths {
		arg = strings.ReplaceAll(arg, placeholder, path)
	}
	return arg
}

func (env *crpcFuzzEnvironment) run(t *testing.T, input io.Reader, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), crpcFuzzRunTimeout)
	defer cancel()
	root := cmd.NewCommand()
	root.SetContext(ctx)
	output, _, err := testcmd.RunStreams(t, root, input, args...)
	return string(output), err
}

// crpcFuzzServer serves reflection and Echo while counting what reaches it.
type crpcFuzzServer struct {
	*httptest.Server
	calls                 *atomic.Int32
	connections, requests atomic.Int64
}

func startCRPCFuzzServer(t *testing.T, secure bool) *crpcFuzzServer {
	t.Helper()
	handler, calls := schemaHandler(t, schemaSet(false), "")
	server := &crpcFuzzServer{calls: calls}
	server.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		server.requests.Add(1)
		handler.ServeHTTP(writer, request)
	}))
	// The server counts a connection when it accepts it, before reading, so any
	// reaction a client observes is already counted when the client returns.
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			server.connections.Add(1)
		}
	}
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetHTTP1(true)
	if secure {
		server.EnableHTTP2 = true
		server.Config.Protocols.SetHTTP2(true)
		server.StartTLS()
	} else {
		server.Config.Protocols.SetUnencryptedHTTP2(true)
		server.Start()
	}
	t.Cleanup(server.Close)
	return server
}

type crpcFuzzTraffic struct{ connections, requests, calls int64 }

func (env *crpcFuzzEnvironment) traffic() crpcFuzzTraffic {
	var total crpcFuzzTraffic
	for _, server := range env.servers {
		total.connections += server.connections.Load()
		total.requests += server.requests.Load()
		total.calls += int64(server.calls.Load())
	}
	return total
}

func (traffic crpcFuzzTraffic) since(before crpcFuzzTraffic) crpcFuzzTraffic {
	return crpcFuzzTraffic{
		connections: traffic.connections - before.connections,
		requests:    traffic.requests - before.requests,
		calls:       traffic.calls - before.calls,
	}
}

func (traffic crpcFuzzTraffic) network() bool {
	return traffic.connections != 0 || traffic.requests != 0
}

func crpcFuzzSlotIndex(tb testing.TB, name string) uint8 {
	tb.Helper()
	for index, slot := range crpcFuzzSlots {
		if slot.name == name {
			return uint8(index)
		}
	}
	tb.Fatalf("unknown fuzz slot %q", name)
	return 0
}

func crpcFuzzElementIndexes(tb testing.TB, names ...string) []byte {
	tb.Helper()
	indexes := make([]byte, 0, len(names))
	for _, name := range names {
		index := -1
		for candidate, element := range crpcFuzzElements {
			if element.name == name {
				index = candidate
			}
		}
		if index < 0 {
			tb.Fatalf("unknown fuzz element %q", name)
		}
		indexes = append(indexes, byte(index))
	}
	return indexes
}
