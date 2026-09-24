package cmd

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNetProtocolDependentDefaultsDoNotMutate(t *testing.T) {
	t.Parallel()
	connect := newNetConnectCmd()
	for _, test := range []struct {
		protocol string
		wait     time.Duration
	}{
		{protocol: netProtocolTCP},
		{protocol: netProtocolUDP, wait: 5 * time.Second},
		{protocol: netProtocolTLS},
		{protocol: netProtocolUDP, wait: 5 * time.Second},
		{protocol: netProtocolTCP},
	} {
		setNetTestProtocol(t, connect, test.protocol)
		wait, err := netConnectWait(connect)
		if err != nil {
			t.Fatal(err)
		}
		if wait != test.wait {
			t.Fatalf("%s wait = %s, want %s", test.protocol, wait, test.wait)
		}
		timeout, err := connect.Flags().GetDuration("timeout")
		if err != nil {
			t.Fatal(err)
		}
		if timeout != 5*time.Second {
			t.Fatalf("%s connector timeout = %s, want 5s", test.protocol, timeout)
		}
	}

	explicitZero := newNetConnectTestCommand(t, netProtocolUDP)
	if err := explicitZero.Flags().Set("wait", "0"); err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{netProtocolTCP, netProtocolUDP, netProtocolTLS} {
		setNetTestProtocol(t, explicitZero, protocol)
		wait, err := netConnectWait(explicitZero)
		if err != nil {
			t.Fatal(err)
		}
		if wait != 0 {
			t.Fatalf("explicit zero wait changed to %s for %s", wait, protocol)
		}
	}

	listen := newNetListenCmd()
	if timeout, err := listen.Flags().GetDuration("timeout"); err != nil || timeout != 0 {
		t.Fatalf("listener timeout = %s, error %v; want 0", timeout, err)
	}
}

func TestNetProtocolCompletionContract(t *testing.T) {
	t.Parallel()
	for _, verb := range []string{"connect", "listen"} {
		for _, selector := range []string{"udp", "tls"} {
			if got := completionLines(completeCommand(t, "net", verb, "--"+selector+"=")); !slices.Equal(got, []string{"true", "false", ":4"}) {
				t.Fatalf("%s --%s completion = %q, want boolean values", verb, selector, got)
			}
		}
		if got := completeCommand(t, "net", verb, "--"); strings.Contains(got, "--protocol\t") {
			t.Fatalf("%s completion still advertises --protocol: %q", verb, got)
		}
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
			shown:  []string{"--wait", "--timeout"},
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
			shown:  []string{"--timeout"},
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
			shown:  []string{"--timeout"},
			hidden: []string{"--wait", "--close-write", "--recv-only", "--cert", "--ca"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			stdout := completeCommand(t, test.args...)
			for _, flag := range test.shown {
				if !strings.Contains(stdout, flag+"\t") {
					t.Errorf("completion %q missing %s", stdout, flag)
				}
			}
			for _, flag := range test.hidden {
				if strings.Contains(stdout, flag+"\t") {
					t.Errorf("completion %q unexpectedly includes %s", stdout, flag)
				}
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
			if got := completionLines(completeCommand(t, args...)); !slices.Equal(got, []string{":4"}) {
				t.Fatalf("inapplicable value completion = %q, want no values and no files", got)
			}
		})
	}
}

func TestNetApplicableFlagValueCompletionRemainsAvailable(t *testing.T) {
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
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := completionLines(completeCommand(t, test.args...)); !slices.Equal(got, test.want) {
				t.Fatalf("applicable value completion = %q, want %q", got, test.want)
			}
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
				"--udp", "--tls", "--timeout", "--wait", "--close-write", "--duplex",
				"--cert", "--key", "--ca", "--system-ca", "--alpn", "--servername", "--insecure",
			},
		},
		{
			verb: "listen",
			flags: []string{
				"--udp", "--tls", "--timeout", "--wait", "--close-write", "--duplex", "--recv-only",
				"--cert", "--key", "--ca", "--system-ca", "--alpn",
			},
		},
	} {
		t.Run(test.verb, func(t *testing.T) {
			t.Parallel()
			stdout, _, err := executeRootStreams(t, "net", test.verb, "--help")
			if err != nil {
				t.Fatal(err)
			}
			_, flagsAndLater, found := strings.Cut(stdout, "\nFlags:\n")
			if !found {
				t.Fatalf("help missing Flags listing:\n%s", stdout)
			}
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
				if !listedFlags[flag] {
					t.Errorf("Flags listing missing %s:\n%s", flag, stdout)
				}
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
