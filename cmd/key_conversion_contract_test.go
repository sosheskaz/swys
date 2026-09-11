package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sosheskaz-systems/npc/internal/asym"
)

func TestKeyPublicTargetsAcrossSupportedAlgorithmsAndInputKinds(t *testing.T) {
	t.Parallel()
	inputs := map[string][]byte{}
	for _, algorithm := range []string{"ed25519", "p256", "p384", "rsa2048"} {
		privatePEM, _, err := executeRootStreams(t, "key", "generate", algorithm)
		if err != nil {
			t.Fatal(err)
		}
		inputs[algorithm] = []byte(privatePEM)
	}
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p521DER, err := x509.MarshalPKCS8PrivateKey(p521)
	if err != nil {
		t.Fatal(err)
	}
	inputs["p521"] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p521DER})

	for algorithm, privateInput := range inputs {
		t.Run(algorithm, func(t *testing.T) {
			t.Parallel()
			privateKey, err := asym.ParseKey(privateInput)
			if err != nil {
				t.Fatal(err)
			}
			publicInput, err := privateKey.Marshal(asym.KeyFormatPKIXPEM)
			if err != nil {
				t.Fatal(err)
			}
			wantInfo, err := privateKey.Info()
			if err != nil {
				t.Fatal(err)
			}
			for inputKind, input := range map[string][]byte{"private": privateInput, "public": publicInput} {
				for _, target := range []string{"pkix-pem", "pkix-der", "openssh"} {
					t.Run(inputKind+"/"+target, func(t *testing.T) {
						t.Parallel()
						output, _, err := executeRootStreamsWithInput(
							t,
							bytes.NewReader(input),
							"key", "public", "--to", target,
						)
						if err != nil {
							t.Fatal(err)
						}
						outputKey, err := asym.ParseKey([]byte(output))
						if err != nil {
							t.Fatal(err)
						}
						gotInfo, err := outputKey.Info()
						if err != nil {
							t.Fatal(err)
						}
						if outputKey.IsPrivate() || gotInfo.PublicKeySHA256Fingerprint != wantInfo.PublicKeySHA256Fingerprint {
							t.Fatalf(
								"output = private:%t fingerprint:%q, want public fingerprint %q",
								outputKey.IsPrivate(),
								gotInfo.PublicKeySHA256Fingerprint,
								wantInfo.PublicKeySHA256Fingerprint,
							)
						}
						if target == "openssh" {
							canonical, err := outputKey.Marshal(asym.KeyFormatOpenSSH)
							if err != nil {
								t.Fatal(err)
							}
							if !bytes.Equal([]byte(output), canonical) || output[len(output)-1] != '\n' {
								t.Fatalf("OpenSSH output is not canonical: %q", output)
							}
							if _, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(output)); err != nil || comment != "" || len(options) != 0 || len(rest) != 0 {
								t.Fatalf("OpenSSH parse = comment:%q options:%q rest:%q err:%v", comment, options, rest, err)
							}
						}
					})
				}
			}
		})
	}
}

func TestKeyConvertPreservesKeyKind(t *testing.T) {
	t.Parallel()
	privatePEM, _, err := executeRootStreams(t, "key", "generate", "ed25519")
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := asym.ParseKey([]byte(privatePEM))
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, err := privateKey.Marshal(asym.KeyFormatPKIXPEM)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct { //nolint:govet // Field order groups the input, target, and expected guidance for each case.
		name     string
		input    []byte
		target   string
		guidance string
	}{
		{name: "private to public", input: []byte(privatePEM), target: "openssh", guidance: "use npc key public --to openssh"},
		{name: "public to private", input: publicPEM, target: "pkcs8-pem"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := executeRootStreamsWithInput(t, bytes.NewReader(test.input), "key", "convert", "--to", test.target)
			if !errors.Is(err, asym.ErrInvalidKeyConversion) {
				t.Fatalf("error = %v, want ErrInvalidKeyConversion", err)
			}
			if test.guidance != "" && !strings.Contains(err.Error(), test.guidance) {
				t.Fatalf("error = %v, want guidance %q", err, test.guidance)
			}
		})
	}
}

func TestKeyConvertAllowsSameKindCanonicalization(t *testing.T) {
	t.Parallel()
	privatePEM, _, err := executeRootStreams(t, "key", "generate", "p256")
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := asym.ParseKey([]byte(privatePEM))
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, err := privateKey.Marshal(asym.KeyFormatPKIXPEM)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct { //nolint:govet // Field order keeps each conversion scenario readable.
		name        string
		input       []byte
		target      string
		wantPrivate bool
	}{
		{name: "private same format", input: []byte(privatePEM), target: "pkcs8-pem", wantPrivate: true},
		{name: "private DER", input: []byte(privatePEM), target: "sec1-der", wantPrivate: true},
		{name: "public same format", input: publicPEM, target: "pkix-pem"},
		{name: "public OpenSSH", input: publicPEM, target: "openssh"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output, _, err := executeRootStreamsWithInput(t, bytes.NewReader(test.input), "key", "convert", "--to", test.target)
			if err != nil {
				t.Fatal(err)
			}
			key, err := asym.ParseKey([]byte(output))
			if err != nil {
				t.Fatal(err)
			}
			if key.IsPrivate() != test.wantPrivate {
				t.Fatalf("private = %t, want %t", key.IsPrivate(), test.wantPrivate)
			}
		})
	}
}

func TestKeyConvertRejectsAlgorithmIncompatiblePrivateTarget(t *testing.T) {
	t.Parallel()
	privatePEM, _, err := executeRootStreams(t, "key", "generate", "p256")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = executeRootStreamsWithInput(
		t,
		strings.NewReader(privatePEM),
		"key", "convert", "--to", "pkcs1-pem",
	)
	if !errors.Is(err, asym.ErrInvalidKeyConversion) {
		t.Fatalf("error = %v, want ErrInvalidKeyConversion", err)
	}
}

func TestKeyPreparationFailuresPreserveDestination(t *testing.T) {
	t.Parallel()
	privatePEM, _, err := executeRootStreams(t, "key", "generate", "p256")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		input []byte
		args  []string
	}{
		{name: "public parse", input: []byte("not a key"), args: []string{"key", "public"}},
		{name: "convert parse", input: []byte("not a key"), args: []string{"key", "convert", "--to", "pkcs8-pem"}},
		{name: "kind mismatch", input: []byte(privatePEM), args: []string{"key", "convert", "--to", "pkix-pem"}},
		{name: "algorithm mismatch", input: []byte(privatePEM), args: []string{"key", "convert", "--to", "pkcs1-pem"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			stdout, _, err := executeRootStreamsWithInput(t, bytes.NewReader(test.input), test.args...)
			if err == nil || stdout != "" {
				t.Fatalf("stdout = %q, err = %v; want an error with no stdout", stdout, err)
			}
			for _, existing := range []bool{false, true} {
				destination := filepath.Join(t.TempDir(), "output")
				if existing {
					if err := os.WriteFile(destination, []byte("preserve"), 0o640); err != nil {
						t.Fatal(err)
					}
				}
				args := append(append([]string(nil), test.args...), "--output", destination)
				if _, _, err := executeRootStreamsWithInput(t, bytes.NewReader(test.input), args...); err == nil {
					t.Fatalf("execute %v succeeded", args)
				}
				data, err := os.ReadFile(destination)
				if existing {
					if err != nil || string(data) != "preserve" {
						t.Fatalf("destination = %q, err = %v", data, err)
					}
				} else if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("destination exists after rejection: %v", err)
				}
			}
		})
	}
}

func TestKeyTargetsValidateBeforeReadingStdin(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"key", "public", "--unknown"},
		{"key", "public", "--to", "missing"},
		{"key", "public", "--to", "pkcs8-pem"},
		{"key", "convert", "--to", "missing"},
	} {
		_, _, err := executeRootStreamsWithInput(t, keyFailingReader{err: errKeyTestReadFailed}, args...)
		if err == nil || errors.Is(err, errKeyTestReadFailed) {
			t.Fatalf("execute %v error = %v, want target validation before stdin", args, err)
		}
	}
}

func TestKeyPublicDiscardsOpenSSHOptionsAndComments(t *testing.T) {
	t.Parallel()
	privateKey, err := asym.ParseKey(generateExampleEd25519Key(t))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := privateKey.Marshal(asym.KeyFormatOpenSSH)
	if err != nil {
		t.Fatal(err)
	}
	input := append([]byte("# workstation\nrestrict,no-agent-forwarding "), bytes.TrimSpace(canonical)...)
	input = append(input, []byte(" developer@example\n")...)
	output, _, err := executeRootStreamsWithInput(
		t,
		bytes.NewReader(input),
		"key", "public", "--to", "openssh",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(output), canonical) {
		t.Fatalf("output = %q, want canonical %q", output, canonical)
	}
}

func TestKeyPublicTargetHelpAndDefault(t *testing.T) {
	t.Parallel()
	command := newKeyPublicCmd()
	flag := command.Flags().Lookup("to")
	if flag == nil || flag.DefValue != "pkix-pem" {
		t.Fatalf("--to default = %v, want pkix-pem", flag)
	}
	for _, text := range []string{"pkix-pem", "pkix-der", "openssh"} {
		if !strings.Contains(flag.Usage, text) {
			t.Fatalf("--to help = %q, want %q", flag.Usage, text)
		}
	}
	if !strings.Contains(newKeyConvertCmd().Long, "Use key public") {
		t.Fatalf("key convert help = %q", newKeyConvertCmd().Long)
	}
}

func TestPreparedKeyOutputIsClearedAcrossCommandReuse(t *testing.T) {
	t.Parallel()
	root := newRootCmd()
	firstKey := generateExampleEd25519Key(t)
	secondPEM, _, err := executeRootStreams(t, "key", "generate", "p256")
	if err != nil {
		t.Fatal(err)
	}

	var first bytes.Buffer
	root.SetIn(keyReaderFunc(bytes.NewReader(firstKey).Read))
	root.SetOut(&first)
	root.SetArgs([]string{"key", "public", "--to", "openssh"})
	if err := executeCommand(root); err != nil {
		t.Fatal(err)
	}
	if first.Len() == 0 {
		t.Fatal("first execution emitted no output")
	}

	var second bytes.Buffer
	root.SetIn(keyReaderFunc(strings.NewReader(secondPEM).Read))
	root.SetOut(&second)
	root.SetArgs([]string{"key", "public", "--to", "pkix-pem"})
	if err := executeCommand(root); err != nil {
		t.Fatal(err)
	}
	secondKey, err := asym.ParseKey(second.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	secondInfo, err := secondKey.Info()
	if err != nil {
		t.Fatal(err)
	}
	if secondInfo.Algorithm != "ecdsa" {
		t.Fatalf("second execution output algorithm = %q, want ecdsa", secondInfo.Algorithm)
	}

	var third bytes.Buffer
	root.SetIn(strings.NewReader("not a key"))
	root.SetOut(&third)
	root.SetArgs([]string{"key", "public", "--to", "openssh"})
	if err := executeCommand(root); err == nil {
		t.Fatal("third execution accepted invalid key")
	}
	if third.Len() != 0 {
		t.Fatalf("third execution reused prepared output: %q", third.String())
	}

	var fourth bytes.Buffer
	root.SetIn(keyReaderFunc(bytes.NewReader(firstKey).Read))
	root.SetOut(&fourth)
	root.SetArgs([]string{"key", "public", "--to", "pkix-pem"})
	if err := executeCommand(root); err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(fourth.Bytes()); block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("fourth execution output = %q", fourth.String())
	}
}

func TestPreparedKeyCommandsPreserveExplicitChildStreams(t *testing.T) {
	t.Parallel()
	privateKey := generateExampleEd25519Key(t)
	parsed, err := asym.ParseKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := parsed.Marshal(asym.KeyFormatPKIXPEM)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		path  []string
		args  []string
		input []byte
	}{
		{name: "public", path: []string{"key", "public"}, args: []string{"key", "public"}, input: privateKey},
		{name: "convert", path: []string{"key", "convert"}, args: []string{"key", "convert", "--to", "openssh"}, input: publicKey},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := newRootCmd()
			command, _, err := root.Find(test.path)
			if err != nil {
				t.Fatal(err)
			}
			input := bytes.NewReader(test.input)
			var output bytes.Buffer
			root.SetIn(input)
			root.SetOut(&output)
			command.SetIn(input)
			command.SetOut(&output)
			root.SetArgs(test.args)
			if err := executeCommand(root); err != nil {
				t.Fatal(err)
			}

			root.SetIn(strings.NewReader("replacement"))
			root.SetOut(&bytes.Buffer{})
			if command.InOrStdin() != input || command.OutOrStdout() != &output {
				t.Fatal("explicit child streams were replaced by inherited root streams")
			}
		})
	}
}

func TestPreparedKeyConvertUsesCurrentInheritedRootStreams(t *testing.T) {
	t.Parallel()
	root := newRootCmd()
	privateEd25519 := generateExampleEd25519Key(t)
	privateP256, _, err := executeRootStreams(t, "key", "generate", "p256")
	if err != nil {
		t.Fatal(err)
	}
	publicInputs := make([][]byte, 0, 2)
	for _, privateInput := range [][]byte{privateEd25519, []byte(privateP256)} {
		key, err := asym.ParseKey(privateInput)
		if err != nil {
			t.Fatal(err)
		}
		publicInput, err := key.Marshal(asym.KeyFormatPKIXPEM)
		if err != nil {
			t.Fatal(err)
		}
		publicInputs = append(publicInputs, publicInput)
	}

	for index, input := range publicInputs {
		var output bytes.Buffer
		root.SetIn(keyReaderFunc(bytes.NewReader(input).Read))
		root.SetOut(&output)
		root.SetArgs([]string{"key", "convert", "--to", "pkix-pem"})
		if err := executeCommand(root); err != nil {
			t.Fatal(err)
		}
		key, err := asym.ParseKey(output.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		info, err := key.Info()
		if err != nil {
			t.Fatal(err)
		}
		wantAlgorithm := []string{"ed25519", "ecdsa"}[index]
		if info.Algorithm != wantAlgorithm {
			t.Fatalf("execution %d algorithm = %q, want %q", index, info.Algorithm, wantAlgorithm)
		}
	}
}

type keyReaderFunc func([]byte) (int, error)

func (read keyReaderFunc) Read(buffer []byte) (int, error) {
	return read(buffer)
}
