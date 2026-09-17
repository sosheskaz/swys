package cmd

import (
	"slices"
	"strings"
	"testing"
)

func TestNetCompletionExamples(t *testing.T) {
	t.Parallel()

	t.Run("choose an ALPN protocol", func(t *testing.T) {
		t.Parallel()
		stdout := completeCommand(t, "net", "connect", "tls", "--alpn", "h")
		want := []string{"h2\tHTTP/2", "http/1.1\tHTTP/1.1", ":38"}
		if got := completionLines(stdout); !slices.Equal(got, want) {
			t.Fatalf("completion = %q, want %q", got, want)
		}
	})

	t.Run("continue an ordered ALPN list", func(t *testing.T) {
		t.Parallel()
		stdout := completeCommand(t, "net", "listen", "tls", "--alpn", "h2,h")
		want := []string{"h2,http/1.1\tHTTP/1.1", ":38"}
		if got := completionLines(stdout); !slices.Equal(got, want) {
			t.Fatalf("completion = %q, want %q", got, want)
		}
	})

	t.Run("choose a response wait", func(t *testing.T) {
		t.Parallel()
		stdout := completeCommand(t, "nc", "connect", "udp", "--wait", "")
		want := []string{
			"0\tWait indefinitely for a response datagram",
			"1s\tOne second",
			"5s\tFive seconds",
			"10s\tTen seconds",
			"30s\tThirty seconds",
			":36",
		}
		if got := completionLines(stdout); !slices.Equal(got, want) {
			t.Fatalf("completion = %q, want %q", got, want)
		}
	})
}

func TestNetALPNCompletion(t *testing.T) {
	t.Parallel()
	want := []string{
		"h2\tHTTP/2",
		"http/1.1\tHTTP/1.1",
		"dot\tDNS over TLS",
		"mqtt\tMQTT",
		"postgresql\tPostgreSQL",
		"imap\tIMAP",
		"pop3\tPOP3",
		"acme-tls/1\tACME TLS-ALPN challenge",
		":38",
	}
	for _, args := range [][]string{
		{"net", "connect", "tls", "--alpn", ""},
		{"netcat", "listen", "tls", "--alpn", ""},
	} {
		if got := completionLines(completeCommand(t, args...)); !slices.Equal(got, want) {
			t.Fatalf("completion for %q = %q, want %q", args, got, want)
		}
	}

	stdout := completeCommand(t, "net", "connect", "tls", "--alpn", "h2,mqtt,")
	lines := completionLines(stdout)
	if lines[len(lines)-1] != ":38" {
		t.Fatalf("completion directive = %q, want no-space, no-file, keep-order", lines[len(lines)-1])
	}
	for _, line := range lines[:len(lines)-1] {
		if strings.HasPrefix(line, "h2,mqtt,h2\t") || strings.HasPrefix(line, "h2,mqtt,mqtt\t") {
			t.Fatalf("completion repeated an ALPN value: %q", line)
		}
		if strings.Contains(strings.SplitN(line, "\t", 2)[0], " ") {
			t.Fatalf("completion inserted a space: %q", line)
		}
	}

	if got := completionLines(completeCommand(t, "net", "connect", "tls", "--alpn", "custom")); !slices.Equal(got, []string{":38"}) {
		t.Fatalf("custom ALPN completion = %q, want directive only", got)
	}
	for _, excluded := range []string{"h2c", "h3", "doq"} {
		if strings.Contains(strings.Join(want, "\n"), excluded+"\t") {
			t.Fatalf("completion advertises excluded protocol %q", excluded)
		}
	}
	if parsed, err := parseALPN("custom-protocol"); err != nil || !slices.Equal(parsed, []string{"custom-protocol"}) {
		t.Fatalf("custom ALPN parsed as %q, error %v", parsed, err)
	}
	if parsed, err := parseALPN(""); err != nil || parsed != nil {
		t.Fatalf("empty ALPN parsed as %q, error %v", parsed, err)
	}
}

func TestNetworkDurationCompletion(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, zero string
		args       []string
	}{
		{name: "connect TCP timeout", args: []string{"net", "connect", "tcp", "--timeout", ""}, zero: "Disable TCP setup and TLS handshake timeout"},
		{name: "connect TLS wait", args: []string{"net", "connect", "tls", "--wait", ""}, zero: "Wait indefinitely while draining the response"},
		{name: "connect UDP timeout", args: []string{"net", "connect", "udp", "--timeout", ""}, zero: "Disable UDP address resolution and socket setup timeout"},
		{name: "connect UDP wait", args: []string{"net", "connect", "udp", "--wait", ""}, zero: "Wait indefinitely for a response datagram"},
		{name: "listen TCP timeout", args: []string{"net", "listen", "tcp", "--timeout", ""}, zero: "Disable bind resolution and accept timeout"},
		{name: "listen TCP wait", args: []string{"net", "listen", "tcp", "--wait", ""}, zero: "Wait indefinitely while draining the response"},
		{name: "listen TLS timeout", args: []string{"net", "listen", "tls", "--timeout", ""}, zero: "Disable bind resolution, accept, and TLS handshake timeout"},
		{name: "listen UDP timeout", args: []string{"net", "listen", "udp", "--timeout", ""}, zero: "Disable bind resolution and first datagram timeout"},
		{name: "certificate connect timeout", args: []string{"cert", "connect", "--timeout", ""}, zero: "Disable TCP setup and TLS handshake timeout"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			lines := completionLines(completeCommand(t, test.args...))
			want := []string{
				"0\t" + test.zero,
				"1s\tOne second",
				"5s\tFive seconds",
				"10s\tTen seconds",
				"30s\tThirty seconds",
				":36",
			}
			if !slices.Equal(lines, want) {
				t.Fatalf("completion = %q, want %q", lines, want)
			}
		})
	}
	command := newNetConnectTCPCmd()
	if err := command.Flags().Set("timeout", "250ms"); err != nil {
		t.Fatalf("set arbitrary duration: %v", err)
	}
	if got, err := command.Flags().GetDuration("timeout"); err != nil || got.String() != "250ms" {
		t.Fatalf("arbitrary duration = %s, error %v", got, err)
	}
	wantPrefix := []string{"1s\tOne second", "10s\tTen seconds", ":36"}
	if got := completionLines(completeCommand(t, "net", "connect", "tcp", "--timeout", "1")); !slices.Equal(got, wantPrefix) {
		t.Fatalf("duration prefix completion = %q", got)
	}
	if newNetListenUDPCmd().Flags().Lookup("wait") != nil {
		t.Fatal("UDP listener unexpectedly gained a wait flag")
	}
}

func TestNetCompletionSuppressesFilesForNonPathValues(t *testing.T) {
	t.Parallel()
	var nonPathCompletions [][]string
	for _, alias := range []string{"net", "nc", "netcat"} {
		for _, direction := range []string{"connect", "listen"} {
			for _, transport := range []string{"tcp", "tls", "udp"} {
				nonPathCompletions = append(nonPathCompletions, []string{alias, direction, transport, ""})
			}
		}
	}
	nonPathCompletions = append(nonPathCompletions,
		[]string{"nc", "connect", "udp", "example.test:53", "extra"},
		[]string{"netcat", "listen", "tls", "9443", "extra"},
		[]string{"net", "connect", "tls", "--servername", "example"},
	)
	for _, args := range nonPathCompletions {
		lines := completionLines(completeCommand(t, args...))
		if lines[len(lines)-1] != ":4" {
			t.Fatalf("completion for %q = %q, want no-file directive", args, lines)
		}
		for _, line := range lines[:len(lines)-1] {
			if !strings.HasPrefix(line, "--") {
				t.Fatalf("completion for %q includes filename-like value %q", args, line)
			}
		}
	}

	if got := completionLines(completeCommand(t, "net", "connect", "tls", "--ca", "fixture")); !slices.Equal(got, []string{":0"}) {
		t.Fatalf("CA path completion = %q, want filesystem fallback", got)
	}
	wantEncodings := []string{"b64", "base32", "base64", "base64url", "hex", "raw", ":4"}
	gotEncodings := completionLines(completeCommand(t, "net", "connect", "tcp", "-e", "h"))
	for index, value := range gotEncodings {
		gotEncodings[index], _, _ = strings.Cut(value, "\t")
	}
	if !slices.Equal(gotEncodings, wantEncodings) {
		t.Fatalf("short encoding completion = %q", gotEncodings)
	}
}

func TestNetTLSConnectConflictCompletion(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		args   []string
		hidden []string
		shown  []string
	}{
		{name: "CA before completion", args: []string{"--ca", "ca.pem"}, hidden: []string{"--insecure"}, shown: []string{"--system-ca", "--cert"}},
		{name: "system CA before completion", args: []string{"--system-ca"}, hidden: []string{"--insecure"}, shown: []string{"--ca", "--cert"}},
		{name: "insecure before completion", args: []string{"--insecure"}, hidden: []string{"--ca", "--system-ca"}, shown: []string{"--cert", "--key"}},
		{name: "false insecure before CA", args: []string{"--insecure=false"}, shown: []string{"--ca", "--system-ca"}},
		{name: "false insecure after CA", args: []string{"--ca", "ca.pem", "--insecure=false"}, shown: []string{"--system-ca", "--cert"}},
		{name: "false system CA", args: []string{"--system-ca=false"}, shown: []string{"--ca", "--insecure"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := append([]string{"net", "connect", "tls"}, test.args...)
			stdout := completeCommand(t, append(args, "--")...)
			for _, flag := range test.hidden {
				if strings.Contains(stdout, flag+"\t") {
					t.Fatalf("completion %q unexpectedly includes %s", stdout, flag)
				}
			}
			for _, flag := range test.shown {
				if !strings.Contains(stdout, flag+"\t") {
					t.Fatalf("completion %q missing %s", stdout, flag)
				}
			}
		})
	}

	stdout := completeCommand(t, "net", "listen", "tls", "--ca", "ca.pem", "--")
	if strings.Contains(stdout, "--insecure\t") {
		t.Fatal("listen unexpectedly exposes connect-only --insecure")
	}
}

func TestNetTLSCompletionDoesNotChangeNormalHelp(t *testing.T) {
	t.Parallel()
	for _, flags := range [][]string{{"--ca", "ca.pem"}, {"--insecure"}, {"--system-ca"}} {
		args := append([]string{"net", "connect", "tls"}, flags...)
		stdout, _, err := executeRootStreams(t, append(args, "--help")...)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"--ca", "--system-ca", "--insecure"} {
			if !strings.Contains(stdout, "\n      "+name+" ") {
				t.Errorf("help after %q omits %s", flags, name)
			}
		}
	}
	_, _, err := executeRootStreams(t, "net", "connect", "tls", "--insecure=invalid")
	if err == nil || strings.Contains(err.Error(), "completion-aware") {
		t.Errorf("boolean parser error = %v, want original parser error", err)
	}
}

func TestNetTLSConflictingValueCompletion(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		args []string
		want []string
	}{
		{args: []string{"--insecure", "--ca", ""}, want: []string{":4"}},
		{args: []string{"--insecure", "--ca="}, want: []string{":4"}},
		{args: []string{"--insecure=false", "--ca", ""}, want: []string{":0"}},
		{args: []string{"--ca", "ca.pem", "--insecure="}, want: []string{"false", ":4"}},
		{args: []string{"--insecure", "--system-ca="}, want: []string{"false", ":4"}},
		{args: []string{"--system-ca", "--insecure="}, want: []string{"false", ":4"}},
		{args: []string{"--system-ca=false", "--insecure="}, want: []string{"true", "false", ":4"}},
	} {
		args := append([]string{"net", "connect", "tls"}, test.args...)
		got := completionLines(completeCommand(t, args...))
		if !slices.Equal(got, test.want) {
			t.Errorf("completion %q = %q, want %q", args, got, test.want)
		}
	}
}

func completeCommand(t *testing.T, args ...string) string {
	t.Helper()
	stdout, _, err := executeRootStreams(t, append([]string{"__complete"}, args...)...)
	if err != nil {
		t.Fatal(err)
	}
	return stdout
}

func completionLines(stdout string) []string {
	return strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
}
