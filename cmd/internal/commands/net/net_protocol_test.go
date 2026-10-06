package net_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/cli/encoding"
)

func TestNetProtocolCompletionContract(t *testing.T) {
	t.Parallel()
	for _, verb := range []string{"connect", "listen"} {
		for _, selector := range []string{"udp", "tls"} {
			got := completionLines(completeCommand(t, "net", verb, "--"+selector+"="))
			assert.Equal(t, []string{"true", "false", ":4"}, got, "%s --%s completion", verb, selector)
		}
		assert.NotContains(t, completeCommand(t, "net", verb, "--"), "--protocol\t", "%s completion", verb)
	}

	for _, test := range []struct {
		name   string
		args   []string
		shown  []string
		hidden []string
	}{
		{
			name:   "default TCP connect",
			args:   []string{"net", "connect", "--"},
			shown:  []string{"--udp", "--tls", "--close-write", "--duplex", "--wait"},
			hidden: []string{"--cert", "--ca", "--servername", "--insecure", "--alpn"},
		},
		{
			name:   "UDP connect",
			args:   []string{"net", "connect", "--udp", "--"},
			shown:  []string{"--wait", "--connect-timeout"},
			hidden: []string{"--tls", "--close-write", "--duplex", "--cert", "--ca", "--alpn"},
		},
		{
			name:   "TLS connect",
			args:   []string{"net", "connect", "--tls", "--"},
			shown:  []string{"--close-write", "--duplex", "--cert", "--ca", "--servername", "--insecure", "--alpn"},
			hidden: []string{"--udp"},
		},
		{
			name:   "false UDP selector keeps TLS available",
			args:   []string{"net", "connect", "--udp=false", "--"},
			shown:  []string{"--tls", "--close-write"},
			hidden: []string{"--cert", "--ca"},
		},
		{
			name:   "false UDP selector keeps TLS completion",
			args:   []string{"net", "connect", "--udp=false", "--tls", "--"},
			shown:  []string{"--cert", "--ca", "--alpn"},
			hidden: []string{"--protocol"},
		},
		{
			name:   "UDP listen",
			args:   []string{"net", "listen", "--udp", "--"},
			shown:  []string{"--connect-timeout"},
			hidden: []string{"--tls", "--wait", "--close-write", "--duplex", "--recv-only", "--cert", "--ca", "--alpn"},
		},
		{
			name:   "TLS listen",
			args:   []string{"net", "listen", "--tls", "--"},
			shown:  []string{"--cert", "--key", "--wait"},
			hidden: []string{"--udp"},
		},
		{
			name:   "false TLS selector keeps UDP available",
			args:   []string{"net", "listen", "--tls=false", "--"},
			shown:  []string{"--udp", "--close-write", "--wait"},
			hidden: []string{"--cert", "--ca"},
		},
		{
			name:   "false TLS selector keeps UDP completion",
			args:   []string{"net", "listen", "--tls=false", "--udp", "--"},
			shown:  []string{"--connect-timeout"},
			hidden: []string{"--wait", "--close-write", "--recv-only", "--cert", "--ca"},
		},
		{
			name: "receive-only excludes sending flags",
			args: []string{"net", "listen", "--recv-only", "--"}, hidden: []string{"--input", "--duplex", "--udp"},
		},
		{
			name:  "last receive-only false restores sending flags",
			args:  []string{"net", "listen", "--recv-only", "--recv-only=false", "--"},
			shown: []string{"--input", "--duplex"}, hidden: []string{"--udp"},
		},
		{
			name:  "flag-looking input path does not select UDP",
			args:  []string{"net", "listen", "--input", "--udp", "--"},
			shown: []string{"--tls", "--duplex"}, hidden: []string{"--cert"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			stdout := completeCommand(t, test.args...)
			for _, flag := range test.shown {
				assert.Contains(t, stdout, flag+"\t", "completion missing %s", flag)
			}
			for _, flag := range test.hidden {
				assert.NotContains(t, stdout, flag+"\t", "completion unexpectedly includes %s", flag)
			}
		})
	}
}

func TestNetInapplicableFlagValueCompletionIsSuppressed(t *testing.T) {
	t.Parallel()
	type completionCase struct {
		verb     string
		protocol string
		flag     string
		boolean  bool
	}
	var tests []completionCase
	for _, flag := range []string{"cert", "key", "ca", "system-ca", "alpn", "servername", "insecure"} {
		tests = append(tests, completionCase{
			verb: "connect", protocol: netProtocolTCP, flag: flag,
			boolean: flag == "system-ca" || flag == "insecure",
		})
	}
	for _, flag := range []string{
		"cert", "key", "ca", "system-ca", "alpn", "servername", "insecure", "close-write", "duplex",
	} {
		tests = append(tests, completionCase{
			verb: "connect", protocol: netProtocolUDP, flag: flag,
			boolean: slices.Contains([]string{"system-ca", "insecure", "close-write", "duplex"}, flag),
		})
	}
	for _, flag := range []string{"cert", "key", "ca", "system-ca", "alpn"} {
		tests = append(tests, completionCase{
			verb: "listen", protocol: netProtocolTCP, flag: flag,
			boolean: flag == "system-ca",
		})
	}
	for _, flag := range []string{
		"cert", "key", "ca", "system-ca", "alpn", "close-write", "duplex", "recv-only", "wait",
	} {
		tests = append(tests, completionCase{
			verb: "listen", protocol: netProtocolUDP, flag: flag,
			boolean: slices.Contains([]string{"system-ca", "close-write", "duplex", "recv-only"}, flag),
		})
	}
	for _, test := range tests {
		name := test.protocol + " " + test.verb + " --" + test.flag
		args := []string{"net", test.verb}
		if test.protocol != netProtocolTCP {
			args = append(args, "--"+test.protocol)
		}
		if test.boolean {
			args = append(args, "--"+test.flag+"=")
		} else {
			args = append(args, "--"+test.flag, "")
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, []string{":4"}, completionLines(completeCommand(t, args...)), "inapplicable value completion")
		})
	}
}

func TestNetFlagValueCompletionContract(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "TLS connect certificate file",
			args: []string{"net", "connect", "--tls", "--cert", ""},
			want: []string{":0"},
		},
		{
			name: "TLS listen key file",
			args: []string{"net", "listen", "--tls", "--key", ""},
			want: []string{":0"},
		},
		{
			name: "TLS connect insecure boolean",
			args: []string{"net", "connect", "--tls", "--insecure="},
			want: []string{"true", "false", ":4"},
		},
		{
			name: "TLS listen system CA boolean",
			args: []string{"net", "listen", "--tls", "--system-ca="},
			want: []string{"true", "false", ":4"},
		},
		{
			name: "TCP connect close-write boolean",
			args: []string{"net", "connect", "--close-write="},
			want: []string{"true", "false", ":4"},
		},
		{
			name: "TCP listen receive-only boolean",
			args: []string{"net", "listen", "--recv-only="},
			want: []string{"true", "false", ":4"},
		},
		{
			name: "receive-only excludes typed input",
			args: []string{"net", "listen", "--recv-only", "--input", ""}, want: []string{":4"},
		},
		{
			name: "receive-only excludes even false duplex",
			args: []string{"net", "listen", "--recv-only", "--duplex="}, want: []string{":4"},
		},
		{
			name: "explicit false duplex excludes receive-only true",
			args: []string{"net", "listen", "--duplex=false", "--recv-only="}, want: []string{"false", ":4"},
		},
		{
			name: "explicit false duplex excludes UDP true",
			args: []string{"net", "listen", "--duplex=false", "--udp="}, want: []string{"false", ":4"},
		},
		{
			name: "ancestor short empty input excludes receive-only true",
			args: []string{"-i", "", "net", "listen", "--recv-only="}, want: []string{"false", ":4"},
		},
		{
			name: "receive-only false permits typed input",
			args: []string{"net", "listen", "--recv-only=false", "--input", ""}, want: []string{":0"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, test.want, completionLines(completeCommand(t, test.args...)), "applicable value completion")
		})
	}
}

func TestNetProtocolHelpDocumentsFullFlagUnion(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		verb  string
		flags []string
	}{
		{
			verb: "connect",
			flags: []string{
				"--udp", "--tls", "--connect-timeout", "--wait", "--close-write", "--duplex",
				"--cert", "--key", "--ca", "--system-ca", "--alpn", "--servername", "--insecure",
			},
		},
		{
			verb: "listen",
			flags: []string{
				"--udp", "--tls", "--connect-timeout", "--wait", "--close-write", "--duplex", "--recv-only",
				"--cert", "--key", "--ca", "--system-ca", "--alpn",
			},
		},
	} {
		t.Run(test.verb, func(t *testing.T) {
			t.Parallel()
			stdout, _, err := executeRootStreams(t, "net", test.verb, "--help")
			require.NoError(t, err)
			_, flagsAndLater, found := strings.Cut(stdout, "\nFlags:\n")
			require.True(t, found, "help missing Flags listing:\n%s", stdout)
			flagsListing, _, _ := strings.Cut(flagsAndLater, "\nGlobal Flags:")
			listedFlags := make(map[string]bool)
			for line := range strings.SplitSeq(flagsListing, "\n") {
				fields := strings.Fields(line)
				if len(fields) == 0 {
					continue
				}
				flag := fields[0]
				if strings.HasPrefix(flag, "-") && !strings.HasPrefix(flag, "--") && len(fields) > 1 {
					flag = fields[1]
				}
				if strings.HasPrefix(flag, "--") {
					listedFlags[strings.TrimSuffix(flag, ",")] = true
				}
			}
			for _, flag := range test.flags {
				assert.True(t, listedFlags[flag], "Flags listing missing %s:\n%s", flag, stdout)
			}
			if listedFlags["--protocol"] || !strings.Contains(flagsListing, "-u, --udp") || !strings.Contains(flagsListing, "-T, --tls") {
				t.Errorf("selector flags in help = %q, want -u/--udp and -T/--tls without --protocol", flagsListing)
			}
			for _, protocol := range []string{"tcp", "udp", "tls"} {
				if strings.Contains(stdout, "Available Commands:") || strings.Contains(stdout, "\n  "+protocol+" ") {
					t.Errorf("help still exposes %s as a subcommand:\n%s", protocol, stdout)
				}
			}
		})
	}
}

func TestNetCompletionDoesNotSuggestLegacyTransportSubcommands(t *testing.T) {
	t.Parallel()
	for _, verb := range []string{"connect", "listen"} {
		lines := completionLines(completeCommand(t, "net", verb, ""))
		for _, line := range lines[:len(lines)-1] {
			value, _, _ := strings.Cut(line, "\t")
			if slices.Contains([]string{"tcp", "udp", "tls"}, value) {
				t.Fatalf("%s completion suggests removed transport subcommand %q", verb, value)
			}
		}
	}
}

func TestNetTLSArtifactValidationPrecedesIO(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		args    []string
		unknown bool
	}{
		{name: "explicit raw needs source", args: []string{"connect", "--tls", "--ca-encoding", "raw"}},
		{name: "unknown codec", args: []string{"connect", "--tls", "--ca", "missing", "--ca-encoding", "invalid"}, unknown: true},
		{name: "plaintext codec", args: []string{"connect", "--ca", "missing", "--ca-encoding", "raw"}},
		{name: "implicit payload", args: []string{"connect", "--tls", "--ca", "-"}},
		{name: "explicit payload", args: []string{"connect", "--tls", "--ca", "-", "--input", "-"}},
		{name: "nonduplex payload", args: []string{"connect", "--tls", "--ca", "-", "--duplex=false"}},
		{name: "listen payload", args: []string{"listen", "--tls", "--cert", "-", "--key", "missing"}},
		{name: "two credentials", args: []string{"listen", "--tls", "--recv-only", "--cert", "-", "--key", "-"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := &unexpectedListenerInputReader{}
			root := newRootCmd()
			root.SetIn(input)
			output := filepath.Join(t.TempDir(), "output")
			require.NoError(t, os.WriteFile(output, []byte("preserved"), 0o600))
			args := append([]string{"net"}, test.args...)
			args = append(args, "127.0.0.1:9", "--output", output)
			stdout, _, err := executeRootCommandStreams(t, root, args...)
			require.Error(t, err)
			if test.unknown {
				require.ErrorIs(t, err, encoding.ErrUnknownInputEncoding)
			} else {
				require.ErrorIs(t, err, errInvalidNetworkFlags)
			}
			assert.Zero(t, input.reads.Load(), "validation read payload or credentials")
			assert.Empty(t, stdout)
			data, readErr := os.ReadFile(output)
			require.NoError(t, readErr)
			assert.Equal(t, "preserved", string(data))
		})
	}
}

func TestNetTLSArtifactEncodingCompletion(t *testing.T) {
	t.Parallel()
	for _, verb := range []string{"connect", "listen"} {
		for _, source := range []string{"ca", "cert", "key"} {
			assert.Equal(t, []string{":4"}, completionLines(completeCommand(t, "net", verb, "--tls", "--"+source+"-encoding", "ba")), "codec without source")
			values := completionLines(completeCommand(t, "net", verb, "--tls", "--"+source, "missing", "--"+source+"-encoding", "ba"))
			assert.Contains(t, strings.Join(values, "\n"), "base64")
			assert.Contains(t, strings.Join(values, "\n"), "base32")
			assert.Equal(t, ":4", values[len(values)-1])
			assert.Equal(t, []string{":4"}, completionLines(completeCommand(t, "net", verb, "--"+source, "missing", "--"+source+"-encoding", "ba")), "plaintext codec")
		}
	}
	assert.Contains(t, completeCommand(t, "net", "connect", "--tls", "--ca", "missing", "--ca-"), "--ca-encoding\t")
	for _, source := range []string{"ca", "cert", "key"} {
		names := completeCommand(t, "net", "connect", "--tls", "--"+source, "missing", "--insecure", "--"+source+"-")
		values := completionLines(completeCommand(t, "net", "connect", "--tls", "--"+source, "missing", "--insecure", "--"+source+"-encoding", "ba"))
		if source == "ca" {
			assert.Equal(t, []string{":4"}, completionLines(names), "insecure mode suppresses the CA companion name")
			assert.Equal(t, []string{":4"}, values, "insecure mode suppresses CA codecs without filename fallback")
			continue
		}
		assert.Contains(t, names, "--"+source+"-encoding\t", "insecure mode retains client identity companion names")
		assert.Contains(t, strings.Join(values, "\n"), "base64")
		assert.Contains(t, strings.Join(values, "\n"), "base32")
		assert.Equal(t, ":4", values[len(values)-1])
	}
}
