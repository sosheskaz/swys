package grpc_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

const (
	grpcFuzzMaxElements   = 8
	grpcFuzzMaxCandidates = 3
	// grpcFuzzRunTimeout only bounds a hung run; local fixtures answer at once.
	grpcFuzzRunTimeout = 20 * time.Second
	// grpcFuzzSlowCompletion is half of completion's own cap.
	grpcFuzzSlowCompletion = time.Second
	grpcFuzzWatch          = grpcFixtureServiceName + "/Watch"
)

// Each input byte selects through a fixed modulus larger than its list, and an
// input naming an unassigned code is skipped, so appending entries never
// reinterprets a recorded input.
const (
	grpcFuzzEndpointCodes = 8
	grpcFuzzSlotCodes     = 16
	grpcFuzzPrefixCodes   = 8
	grpcFuzzElementCodes  = 128
)

func grpcFuzzPick[T any](values []T, choice byte, codes int) (T, bool) {
	var zero T
	if index := int(choice) % codes; index < len(values) {
		return values[index], true
	}
	return zero, false
}

// grpcFuzzStdinFlags read original stdin when their value is an exact dash.
var grpcFuzzStdinFlags = []string{"ca", "cert", "key", "auth-bearer-file", "auth-basic-file"}

// grpcFuzzEndpoints are the HOST:PORT argument: the two fixtures and two invalid forms.
var grpcFuzzEndpoints = []string{"{plain}", "{tls}", "127.0.0.1:0", "127.0.0.1"}

// grpcFuzzElement is one argument group the fuzzer places on a command line.
// Append new elements only: checked-in corpora select elements by index.
type grpcFuzzElement struct {
	// changes maps each flag the group sets to whether its value is stdin.
	changes   map[string]bool
	name      string
	args      []string
	selector  bool
	streaming bool
}

func grpcFuzzFlag(name string, args []string, flags ...string) grpcFuzzElement {
	changes := make(map[string]bool, len(flags))
	for _, flag := range flags {
		changes[flag] = args[len(args)-1] == "-" || strings.HasSuffix(args[len(args)-1], "=-")
	}
	return grpcFuzzElement{name: name, args: args, changes: changes}
}

var grpcFuzzElements = []grpcFuzzElement{
	grpcFuzzFlag("plaintext", []string{"--plaintext"}, "plaintext"),
	grpcFuzzFlag("plaintext-false", []string{"--plaintext=false"}, "plaintext"),
	grpcFuzzFlag("protoset", []string{"--protoset", "{protoset}"}, "protoset"),
	grpcFuzzFlag("protoset-missing", []string{"--protoset", "{missing}"}, "protoset"),
	grpcFuzzFlag("protoset-directory", []string{"--protoset", "{dir}"}, "protoset"),
	grpcFuzzFlag("protoset-empty", []string{"--protoset="}, "protoset"),
	{name: "selector-unary", args: []string{grpcFixtureMethodName}, selector: true},
	{name: "selector-streaming", args: []string{grpcFuzzWatch}, selector: true, streaming: true},
	{name: "selector-missing", args: []string{grpcFixtureServiceName + "/Missing"}, selector: true},
	{name: "selector-invalid", args: []string{"noslash"}, selector: true},
	grpcFuzzFlag("list", []string{"--list", grpcFixtureServiceName}, "list"),
	grpcFuzzFlag("list-empty", []string{"--list="}, "list"),
	grpcFuzzFlag("describe", []string{"--describe", "fixture.v1.EchoRequest"}, "describe"),
	grpcFuzzFlag("describe-empty", []string{"--describe="}, "describe"),
	grpcFuzzFlag("template", []string{"--template", grpcFixtureMethodName}, "template"),
	grpcFuzzFlag("template-empty", []string{"--template="}, "template"),
	grpcFuzzFlag("data", []string{"-d", "{}"}, "data"),
	grpcFuzzFlag("input", []string{"-i", "{request}"}, "input"),
	grpcFuzzFlag("input-stdin", []string{"-i", "-"}, "input"),
	grpcFuzzFlag("input-empty", []string{"--input="}, "input"),
	grpcFuzzFlag("header", []string{"-H", "x-fuzz: 1"}, "header"),
	grpcFuzzFlag("header-invalid", []string{"-H", "bad header"}, "header"),
	grpcFuzzFlag("header-authorization", []string{"-H", "authorization: Bearer header-token"}, "header"),
	grpcFuzzFlag("ca", []string{"--ca", "{ca}"}, "ca"),
	grpcFuzzFlag("ca-stdin", []string{"--ca", "-"}, "ca"),
	grpcFuzzFlag("ca-missing", []string{"--ca", "{missing}"}, "ca"),
	grpcFuzzFlag("system-ca", []string{"--system-ca"}, "system-ca"),
	grpcFuzzFlag("insecure", []string{"--insecure"}, "insecure"),
	grpcFuzzFlag("insecure-no-verify", []string{"--insecure-no-verify"}, "insecure-no-verify"),
	grpcFuzzFlag("servername", []string{"--servername", "localhost"}, "servername"),
	grpcFuzzFlag("cert", []string{"--cert", "{cert}"}, "cert"),
	grpcFuzzFlag("key", []string{"-k", "{key}"}, "key"),
	grpcFuzzFlag("cert-stdin", []string{"--cert", "-"}, "cert"),
	grpcFuzzFlag("key-stdin", []string{"--key=-"}, "key"),
	grpcFuzzFlag("bearer", []string{"--auth-bearer", "token"}, "auth-bearer"),
	grpcFuzzFlag("bearer-file", []string{"--auth-bearer-file", "{token}"}, "auth-bearer-file"),
	grpcFuzzFlag("bearer-file-stdin", []string{"--auth-bearer-file", "-"}, "auth-bearer-file"),
	grpcFuzzFlag("basic", []string{"--auth-basic", "user:pass"}, "auth-basic"),
	grpcFuzzFlag("basic-file", []string{"--auth-basic-file", "{basic}"}, "auth-basic-file"),
	grpcFuzzFlag("basic-file-stdin", []string{"--auth-basic-file=-"}, "auth-basic-file"),
	grpcFuzzFlag("cleartext-auth", []string{"--insecure-cleartext-auth"}, "insecure-cleartext-auth"),
	grpcFuzzFlag("output", []string{"-o", "{out}"}, "output"),
	grpcFuzzFlag("output-protoset", []string{"-o", "{protoset}"}, "output"),
	grpcFuzzFlag("format-json", []string{"-f", "json"}, "format"),
	grpcFuzzFlag("format-text", []string{"--format", "text"}, "format"),
	grpcFuzzFlag("format-invalid", []string{"--format", "yaml"}, "format"),
	grpcFuzzFlag("timeout", []string{"-t", "30s"}, "timeout"),
	grpcFuzzFlag("timeout-negative", []string{"--timeout=-1s"}, "timeout"),
	grpcFuzzFlag("max-message-size-zero", []string{"--max-message-size", "0"}, "max-message-size"),
	grpcFuzzFlag("verbose", []string{"-v"}, "verbose"),
	grpcFuzzFlag("encoding-invalid", []string{"-e", "bogus"}, "encoding"),
	grpcFuzzFlag("ca-encoding-base64", []string{"--ca-encoding", "base64"}, "ca-encoding"),
	grpcFuzzFlag("mode", []string{"--mode", "0600"}, "mode"),
	grpcFuzzFlag("mode-invalid", []string{"--mode=rwx"}, "mode"),
	grpcFuzzFlag("input-missing", []string{"-i", "{missing}"}, "input"),
	grpcFuzzFlag("bearer-empty", []string{"--auth-bearer="}, "auth-bearer"),
	grpcFuzzFlag("basic-invalid", []string{"--auth-basic", "nocolon"}, "auth-basic"),
}

// grpcFuzzSlot is the word being completed. An empty flag completes the method selector.
type grpcFuzzSlot struct {
	name string
	flag string
	// fill is a valid value used to execute the line when completion offered none.
	fill     string
	prefixes []string
	// static candidates are fixed words rather than schema-derived ones.
	static bool
	// data slots complete the request body, in any spelling of -d.
	data bool
	// joined slots type the value in the flag's own word, as in --data=VALUE.
	joined bool
}

var grpcFuzzSlots = []grpcFuzzSlot{
	{name: "selector", prefixes: []string{"", "fixture.", grpcFixtureServiceName + "/", grpcFixtureServiceName + "/E", "zz"}, fill: grpcFixtureMethodName},
	{name: "list", flag: "--list", prefixes: []string{"", "fixture.", "zz"}, fill: grpcFixtureServiceName},
	{
		// Completion reflects lazily, listing services before their files, so the
		// fill is a symbol reachable from every prefix it extends.
		name: "describe", flag: "--describe", fill: grpcFixtureServiceName,
		prefixes: []string{"", "fixture.v1.", grpcFixtureServiceName + ".", "fixture.v1.EchoRequest", "zz"},
	},
	{name: "template", flag: "--template", prefixes: []string{"", "fixture.", grpcFixtureServiceName + "/", "zz"}, fill: grpcFixtureMethodName},
	{name: "data", flag: "--data", prefixes: grpcFuzzDataPrefixes, fill: "{}", data: true},
	{name: "format", flag: "--format", prefixes: []string{"", "j", "t"}, fill: "json", static: true},
	{name: "flag-name", prefixes: []string{"-", "--", "--p", "--auth-"}, fill: grpcFixtureMethodName, static: true},
	{name: "data-short", flag: "-d", prefixes: grpcFuzzDataPrefixes, fill: "{}", data: true},
	{name: "data-inline", flag: "--data=", prefixes: grpcFuzzDataPrefixes, fill: "{}", data: true, joined: true},
	// -v is boolean, so pflag gives the cluster's value to -d.
	{name: "data-cluster", flag: "-vd", prefixes: grpcFuzzDataPrefixes, fill: "{}", data: true},
	{name: "data-cluster-inline", flag: "-vd=", prefixes: grpcFuzzDataPrefixes, fill: "{}", data: true, joined: true},
	{name: "list-inline", flag: "--list=", prefixes: []string{"", "fixture.", "zz"}, fill: grpcFixtureServiceName, joined: true},
}

var grpcFuzzDataPrefixes = []string{"", "{", `'{"`, `"{"`, "zz"}

// FuzzGRPCCompletionStaysWithinExecution checks completion against the command
// line it completes: completion must never call a method, read stdin, or create
// output; must follow the documented -d quiet rules; and may contact the server
// or offer a schema-derived candidate only when execution would accept the same
// line rather than reject it before any network use.
func FuzzGRPCCompletionStaysWithinExecution(f *testing.F) {
	for _, slot := range grpcFuzzSlots {
		if len(slot.prefixes) > grpcFuzzPrefixCodes {
			f.Fatalf("slot %s outgrew its prefix codes", slot.name)
		}
	}
	if len(grpcFuzzEndpoints) > grpcFuzzEndpointCodes || len(grpcFuzzSlots) > grpcFuzzSlotCodes || len(grpcFuzzElements) > grpcFuzzElementCodes {
		f.Fatal("a fuzz vocabulary outgrew its codes")
	}
	// Only the client certificate and key are used; servers present their own leaf.
	identity := testcmd.CreateNetworkIdentity(f, newRootCmd)
	add := func(endpoint uint8, slot string, prefix uint8, elements ...string) {
		f.Add(endpoint, grpcFuzzSlotIndex(f, slot), prefix, grpcFuzzElementIndexes(f, elements...))
	}
	add(0, "selector", 2, "plaintext")
	add(1, "selector", 2, "ca")
	add(1, "describe", 2, "ca", "bearer")
	add(0, "list", 0, "protoset", "plaintext")
	add(0, "template", 2, "plaintext", "header")
	add(0, "data", 0, "protoset", "plaintext", "selector-unary")
	add(0, "data", 0, "plaintext", "selector-unary", "cleartext-auth", "bearer")
	// Typed -d completion once reflected with credentials beside a discovery flag.
	add(0, "data", 0, "plaintext", "selector-unary", "cleartext-auth", "bearer", "list")
	add(0, "data", 0, "protoset", "plaintext", "selector-unary", "template-empty")
	// A stdin credential once failed to silence -d completion from a protoset.
	add(0, "data", 0, "protoset", "plaintext", "selector-unary", "cleartext-auth", "bearer-file-stdin")
	add(0, "data", 0, "protoset", "plaintext", "selector-unary", "cleartext-auth", "bearer", "basic-file-stdin")
	add(0, "data", 1, "protoset", "plaintext", "selector-streaming")
	add(1, "selector", 2, "ca", "timeout-negative")
	// An offline SERVICE/ prefix is checked through the fill that completes it.
	add(0, "selector", 0, "plaintext", "protoset", "timeout-negative")
	// Completion once lost the template for -d typed after a boolean shorthand.
	add(0, "data-cluster", 0, "protoset", "plaintext", "selector-unary")
	add(0, "data-cluster-inline", 1, "protoset", "plaintext", "selector-unary")
	// A supplied --ca follows --ca-encoding; completion never reads TLS contents.
	add(1, "data", 0, "protoset", "selector-unary", "ca", "ca-encoding-base64")

	f.Fuzz(func(t *testing.T, endpointChoice, slotChoice, prefixChoice uint8, choices []byte) {
		line, prefix, ok := decodeGRPCFuzzLine(endpointChoice, slotChoice, prefixChoice, choices)
		if !ok {
			t.Skip("input names an unassigned code")
		}
		line.env = newGRPCFuzzEnvironment(t, &identity)
		if violation := line.check(t, prefix); violation != nil {
			t.Fatalf("%s: %s", violation.rule, violation.detail)
		}
	})
}

func decodeGRPCFuzzLine(endpointChoice, slotChoice, prefixChoice uint8, choices []byte) (*grpcFuzzLine, string, bool) {
	endpoint, endpointOK := grpcFuzzPick(grpcFuzzEndpoints, endpointChoice, grpcFuzzEndpointCodes)
	slot, slotOK := grpcFuzzPick(grpcFuzzSlots, slotChoice, grpcFuzzSlotCodes)
	prefix, prefixOK := grpcFuzzPick(slot.prefixes, prefixChoice, grpcFuzzPrefixCodes)
	line := &grpcFuzzLine{endpoint: endpoint, slot: slot}
	for _, choice := range choices[:min(len(choices), grpcFuzzMaxElements)] {
		element, ok := grpcFuzzPick(grpcFuzzElements, choice, grpcFuzzElementCodes)
		if !ok {
			return nil, "", false
		}
		line.elements = append(line.elements, element)
	}
	return line, prefix, endpointOK && slotOK && prefixOK
}

type grpcFuzzLine struct {
	env      *grpcFuzzEnvironment
	endpoint string
	elements []grpcFuzzElement
	slot     grpcFuzzSlot
}

// grpcFuzzViolation names a broken contract; rule groups equivalent findings.
type grpcFuzzViolation struct {
	rule, detail string
}

func (line *grpcFuzzLine) check(t *testing.T, prefix string) *grpcFuzzViolation {
	t.Helper()
	completionArgs := line.withSlot(prefix)
	stdin := &countingReader{source: strings.NewReader("")}
	protoset := line.env.protoset(t)
	before := line.env.traffic()
	started := time.Now()
	output, err := line.env.run(t, stdin, append([]string{"__complete", "grpc"}, completionArgs...)...)
	elapsed := time.Since(started)
	completion := line.env.traffic().since(before)
	if err != nil {
		return &grpcFuzzViolation{rule: "completion failed", detail: fmt.Sprintf("complete %q: %v", completionArgs, err)}
	}
	finals, partials := grpcFuzzCandidates(t, output)
	report := func(rule, detail string) *grpcFuzzViolation {
		return &grpcFuzzViolation{rule: rule, detail: fmt.Sprintf(
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
		case line.streamingSelector():
			return report("streaming template", "-d offered a template for a streaming method")
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
	expected := line.expectsCompletion(prefix) && elapsed < grpcFuzzSlowCompletion
	var fillRun grpcFuzzRun
	if completion.network() || offered || expected {
		fillRun = line.execute(t, line.slot.fill)
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
	for _, candidate := range grpcFuzzSample(finals) {
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

// expectsCompletion reports whether a successful execution with the fill obliges
// completion to offer it: the fill must extend the typed prefix and no documented
// quiet rule may apply. Lines with a stdin TLS or credential file never get here.
func (line *grpcFuzzLine) expectsCompletion(prefix string) bool {
	switch {
	case line.slot.static:
		return false
	case line.slot.data:
		// The template is compact protobuf JSON for a message with fields, so it
		// starts with {" whatever quote the shell word opens with.
		return slices.Contains([]string{"", "{", `{"`}, strings.TrimLeft(prefix, `'"`)) && !line.changed("input") &&
			!line.changed("list") && !line.changed("describe") && !line.changed("template") && !line.streamingSelector()
	default:
		return strings.HasPrefix(line.slot.fill, prefix)
	}
}

// offers reports whether completion offered the fill or, for -d, a template;
// executed reports whether an offered final word ran successfully, so a stray
// word cannot pass for a request template.
func (line *grpcFuzzLine) offers(finals, partials []string, executed bool) bool {
	if line.slot.data {
		return executed
	}
	return slices.Contains(finals, line.slot.fill) ||
		slices.ContainsFunc(partials, func(partial string) bool { return strings.HasPrefix(line.slot.fill, partial) })
}

// withSlot returns the line's arguments with value typed in the completed slot.
func (line *grpcFuzzLine) withSlot(value string) []string {
	switch {
	case line.slot.joined:
		return append(line.args(), line.slot.flag+value)
	case line.slot.flag != "":
		return append(line.args(), line.slot.flag, value)
	default:
		return append(line.args(), value)
	}
}

// grpcFuzzRun is one execution of the line with a value in the completed slot.
type grpcFuzzRun struct {
	err     error
	args    []string
	traffic grpcFuzzTraffic
}

// rejected reports a failure before either fixture was reached.
func (run grpcFuzzRun) rejected() bool { return run.err != nil && !run.traffic.network() }

func (run grpcFuzzRun) String() string {
	result := "ok"
	if run.err != nil {
		result = run.err.Error()
	}
	return "grpc " + strings.Join(run.args, " ") + ": " + result
}

func (line *grpcFuzzLine) execute(t *testing.T, value string) grpcFuzzRun {
	t.Helper()
	args := line.withSlot(value)
	if line.slot.flag == "" && !line.changed("data") && !line.changed("input") {
		args = append(args, "--data", "{}")
	}
	before := line.env.traffic()
	_, err := line.env.run(t, strings.NewReader("{}"), append([]string{"grpc"}, args...)...)
	return grpcFuzzRun{err: err, args: args, traffic: line.env.traffic().since(before)}
}

func (line *grpcFuzzLine) args() []string {
	args := []string{line.env.expand(line.endpoint)}
	for _, element := range line.elements {
		for _, arg := range element.args {
			// Supplied TLS files follow the line's encoding, so their contents
			// never cause a rejection; completion deliberately does not read them.
			if arg == "{ca}" && line.lastChange("ca-encoding") == "ca-encoding-base64" {
				arg = "{ca-base64}"
			}
			args = append(args, line.env.expand(arg))
		}
	}
	return args
}

// lastChange names the last element that set flag, following pflag's
// last-value-wins rule, or returns "" when none did.
func (line *grpcFuzzLine) lastChange(flag string) string {
	name := ""
	for _, element := range line.elements {
		if _, ok := element.changes[flag]; ok {
			name = element.name
		}
	}
	return name
}

func (line *grpcFuzzLine) changed(flag string) bool {
	for _, element := range line.elements {
		if _, ok := element.changes[flag]; ok {
			return true
		}
	}
	return false
}

// stdinArtifact applies pflag's last-value-wins rule to each stdin-capable flag.
func (line *grpcFuzzLine) stdinArtifact() bool {
	for _, flag := range grpcFuzzStdinFlags {
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

func (line *grpcFuzzLine) streamingSelector() bool {
	var selectors []grpcFuzzElement
	for _, element := range line.elements {
		if element.selector {
			selectors = append(selectors, element)
		}
	}
	return len(selectors) == 1 && selectors[0].streaming
}

// grpcFuzzCandidates returns the final words completion offered and its partial
// words, whose trailing slash continues to a method.
func grpcFuzzCandidates(t *testing.T, output string) ([]string, []string) {
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

func grpcFuzzSample(candidates []string) []string {
	if len(candidates) <= grpcFuzzMaxCandidates {
		return candidates
	}
	return []string{candidates[0], candidates[len(candidates)/2], candidates[len(candidates)-1]}
}

type grpcFuzzEnvironment struct {
	paths     map[string]string
	outPath   string
	recorders []*grpcFixtureRecorder
}

func newGRPCFuzzEnvironment(t *testing.T, identity *testcmd.NetworkIdentity) *grpcFuzzEnvironment {
	t.Helper()
	files, set, request := grpcFixtureSchema(t)
	plainAddress, plainRecorder := startGRPCFixtureWithSchema(t, grpcFixtureReflectionBoth, nil, files, set, request)
	// The self-signed leaf names 127.0.0.1, so --ca with it alone verifies the fixture.
	certificate, caPEM := grpcFixtureCertificate(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	tlsAddress, tlsRecorder := startGRPCFixtureWithSchema(t, grpcFixtureReflectionBoth, tlsConfig, files, set, request)
	directory := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return path
	}
	env := &grpcFuzzEnvironment{
		recorders: []*grpcFixtureRecorder{plainRecorder, tlsRecorder},
		outPath:   filepath.Join(directory, "out.json"),
	}
	env.paths = map[string]string{
		"{plain}":     plainAddress,
		"{tls}":       tlsAddress,
		"{protoset}":  writeGRPCFixtureProtoset(t, set),
		"{request}":   write("request.json", "{}"),
		"{token}":     write("token", "token\n"),
		"{basic}":     write("basic", "user:pass\n"),
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
func (env *grpcFuzzEnvironment) protoset(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(env.paths["{protoset}"])
	if err != nil {
		t.Fatalf("read fixture protoset: %v", err)
	}
	return data
}

func (env *grpcFuzzEnvironment) expand(arg string) string {
	for placeholder, path := range env.paths {
		arg = strings.ReplaceAll(arg, placeholder, path)
	}
	return arg
}

func (env *grpcFuzzEnvironment) run(t *testing.T, input io.Reader, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), grpcFuzzRunTimeout)
	defer cancel()
	root := newRootCmd()
	root.SetContext(ctx)
	output, _, err := testcmd.RunStreams(t, root, input, args...)
	return string(output), err
}

type grpcFuzzTraffic struct{ connections, reflections, calls int }

// traffic sums both fixtures. Each fixture counts a connection when it accepts
// it, before the server reads, so any server reaction a client observes is
// already counted when the client returns.
func (env *grpcFuzzEnvironment) traffic() grpcFuzzTraffic {
	var total grpcFuzzTraffic
	for _, recorder := range env.recorders {
		v1, alpha := recorder.reflectionCounts()
		calls, _, _ := recorder.snapshot()
		total.connections += recorder.connectionCount()
		total.reflections += v1 + alpha
		total.calls += calls
	}
	return total
}

func (traffic grpcFuzzTraffic) since(before grpcFuzzTraffic) grpcFuzzTraffic {
	return grpcFuzzTraffic{
		connections: traffic.connections - before.connections,
		reflections: traffic.reflections - before.reflections,
		calls:       traffic.calls - before.calls,
	}
}

func (traffic grpcFuzzTraffic) network() bool {
	return traffic.connections != 0 || traffic.reflections != 0 || traffic.calls != 0
}

func grpcFuzzSlotIndex(tb testing.TB, name string) uint8 {
	tb.Helper()
	for index, slot := range grpcFuzzSlots {
		if slot.name == name {
			return uint8(index)
		}
	}
	tb.Fatalf("unknown fuzz slot %q", name)
	return 0
}

func grpcFuzzElementIndexes(tb testing.TB, names ...string) []byte {
	tb.Helper()
	indexes := make([]byte, 0, len(names))
	for _, name := range names {
		index := -1
		for candidate, element := range grpcFuzzElements {
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
