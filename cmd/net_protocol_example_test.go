package cmd

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestExampleNetProtocolSelectionUDPShortFlag(t *testing.T) {
	t.Parallel()
	address, serverResult := startExampleUDPServer(t, []byte("response"))

	stdout, stderr, err := executeRootStreamsWithInput(
		t,
		strings.NewReader("request"),
		"net", "connect", "-u", "--tls=false", address,
		"--wait", "1s",
	)
	if err != nil {
		t.Fatalf("UDP exchange: %v", err)
	}
	if stdout != "response" || stderr != "" {
		t.Fatalf("UDP output = %q, stderr = %q", stdout, stderr)
	}
	if result := <-serverResult; result.err != nil || result.request != "request" {
		t.Fatalf("server result = %+v", result)
	}
}

func TestNetProtocolValidationPrecedesOutputIO(t *testing.T) {
	t.Parallel()
	missingInput := filepath.Join(t.TempDir(), "missing-input")
	missingCredential := filepath.Join(t.TempDir(), "missing-credential")

	for _, test := range []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "connect rejects conflicting selectors before file access",
			args: []string{"net", "connect", "--udp=true", "--tls=true", "127.0.0.1:1", "--cert", missingCredential, "--input", missingInput},
			want: []string{"--udp", "--tls"},
		},
		{
			name: "listen rejects conflicting selectors before file access",
			args: []string{"net", "listen", "--udp", "--tls", "127.0.0.1:0", "--cert", missingCredential, "--key", missingCredential, "--input", missingInput},
			want: []string{"--udp", "--tls"},
		},
		{
			name: "TCP rejects explicit TLS flag",
			args: []string{
				"net", "connect", "127.0.0.1:1",
				"--cert", missingCredential, "--input", missingInput,
			},
			want: []string{"--cert", "--tls"},
		},
		{
			name: "UDP rejects explicit false stream flag",
			args: []string{
				"net", "connect", "--udp", "127.0.0.1:1",
				"--close-write=false", "--input", missingInput,
			},
			want: []string{"--close-write", "udp"},
		},
		{
			name: "UDP rejects explicit stream flag at its true default",
			args: []string{
				"net", "connect", "--udp", "127.0.0.1:1",
				"--close-write=true", "--input", missingInput,
			},
			want: []string{"--close-write", "udp"},
		},
		{
			name: "UDP rejects explicit duplex default",
			args: []string{
				"net", "connect", "--udp", "127.0.0.1:1",
				"--duplex=true", "--input", missingInput,
			},
			want: []string{"--duplex", "udp"},
		},
		{
			name: "TCP rejects explicit false TLS flag",
			args: []string{
				"net", "connect", "--tls=false", "127.0.0.1:1",
				"--insecure=false", "--input", missingInput,
			},
			want: []string{"--insecure", "--tls"},
		},
		{
			name: "UDP rejects explicit false TLS flag",
			args: []string{
				"net", "listen", "--udp", "127.0.0.1:0",
				"--system-ca=false", "--input", missingInput,
			},
			want: []string{"--system-ca", "--tls"},
		},
		{
			name: "TCP rejects explicit empty TLS flag",
			args: []string{
				"net", "connect", "127.0.0.1:1",
				"--alpn=", "--input", missingInput,
			},
			want: []string{"--alpn", "--tls"},
		},
		{
			name: "UDP listener rejects explicit zero wait",
			args: []string{
				"net", "listen", "--udp", "127.0.0.1:0",
				"--wait=0", "--input", missingInput,
			},
			want: []string{"--wait", "udp"},
		},
		{
			name: "UDP listener rejects explicit false receive-only",
			args: []string{
				"net", "listen", "--udp", "127.0.0.1:0",
				"--recv-only=false", "--input", missingInput,
			},
			want: []string{"--recv-only", "udp"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			outputPath := filepath.Join(t.TempDir(), "output")
			const sentinel = "preserve existing output"
			if err := os.WriteFile(outputPath, []byte(sentinel), 0o600); err != nil {
				t.Fatal(err)
			}
			args := append(append([]string{}, test.args...), "--output", outputPath)
			_, _, err := executeRootStreams(t, args...)
			if err == nil {
				t.Fatal("invalid protocol selection succeeded")
			}
			for _, want := range test.want {
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
					t.Fatalf("error = %q, want %q", err, want)
				}
			}
			if strings.Contains(err.Error(), missingInput) || strings.Contains(err.Error(), missingCredential) {
				t.Fatalf("selector validation reached input or credential path: %q", err)
			}
			output, readErr := os.ReadFile(outputPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(output) != sentinel {
				t.Fatalf("invalid protocol selection changed output to %q", output)
			}
		})
	}
}

func TestNetRemovedProtocolFlagsAreRejected(t *testing.T) {
	t.Parallel()
	for _, verb := range []string{"connect", "listen"} {
		for _, flag := range []string{"--protocol", "-p"} {
			t.Run(verb+" "+flag, func(t *testing.T) {
				t.Parallel()
				_, _, err := executeRootStreams(t, "net", verb, flag, "tcp")
				if err == nil || !strings.Contains(err.Error(), "unknown") {
					t.Fatalf("removed %s error = %v, want unknown flag", flag, err)
				}
			})
		}
	}
}

func TestNetTLSListenerRequiresIdentityBeforeIO(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "input")
	if err := os.WriteFile(inputPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	const sentinel = "preserve existing output"
	for _, test := range []struct {
		name  string
		input string
		flags []string
	}{
		{name: "both missing before missing input", input: filepath.Join(directory, "missing-input")},
		{name: "both missing preserve output", input: inputPath},
		{name: "key missing before certificate read", input: inputPath, flags: []string{"--cert", filepath.Join(directory, "missing-cert")}},
		{name: "certificate missing before key read", input: inputPath, flags: []string{"--key", filepath.Join(directory, "missing-key")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			outputPath := filepath.Join(t.TempDir(), "output")
			if err := os.WriteFile(outputPath, []byte(sentinel), 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{
				"net", "listen", "--tls", "127.0.0.1:0",
				"--input", test.input, "--output", outputPath,
			}
			args = append(args, test.flags...)
			_, _, err := executeRootStreams(t, args...)
			if err == nil || !strings.Contains(err.Error(), "--cert") || !strings.Contains(err.Error(), "--key") {
				t.Fatalf("missing TLS identity error = %q, want cert/key requirement", err)
			}
			output, readErr := os.ReadFile(outputPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(output) != sentinel {
				t.Fatalf("missing TLS identity changed output to %q", output)
			}
		})
	}
}

func TestNetLegacyTransportSyntaxShowsMigration(t *testing.T) {
	t.Parallel()

	for _, verb := range []string{"connect", "listen"} {
		for _, protocol := range []string{"tcp", "udp", "tls"} {
			t.Run(verb+" "+protocol, func(t *testing.T) {
				t.Parallel()
				_, _, err := executeRootStreams(t, "net", verb, protocol, "invalid-endpoint")
				if err == nil {
					t.Fatal("legacy transport syntax succeeded")
				}
				want := map[string]string{
					"tcp": "net " + verb + " <endpoint>",
					"udp": "net " + verb + " --udp <endpoint>",
					"tls": "net " + verb + " --tls <endpoint>",
				}[protocol]
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("legacy syntax error = %q, want migration form %q", err, want)
				}
				if strings.Contains(err.Error(), "--protocol") {
					t.Fatalf("legacy syntax error still suggests removed flag: %q", err)
				}
			})
		}
	}
}

func newNetConnectTestCommand(t *testing.T, protocol string) *cobra.Command {
	t.Helper()
	command := newNetConnectCmd()
	setNetTestProtocol(t, command, protocol)
	return command
}

func newNetListenTestCommand(t *testing.T, protocol string) *cobra.Command {
	t.Helper()
	command := newNetListenCmd()
	setNetTestProtocol(t, command, protocol)
	return command
}

func setNetTestProtocol(t *testing.T, command *cobra.Command, protocol string) {
	t.Helper()
	for _, selector := range []string{"udp", "tls"} {
		if command.Flags().Lookup(selector) == nil {
			t.Fatalf("net %s has no --%s flag", command.Name(), selector)
		}
		if err := command.Flags().Set(selector, strconv.FormatBool(selector == protocol)); err != nil {
			t.Fatal(err)
		}
	}
}
