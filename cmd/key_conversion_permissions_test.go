package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sosheskaz-systems/npc/internal/asym"
	"github.com/sosheskaz-systems/npc/internal/securefile"
)

func TestKeyConvertOutputPermissions(t *testing.T) {
	// Root command execution mutates shared flags, so these cases cannot run in parallel.
	for _, target := range []string{"pkcs8-pem", "pkcs8-der", "pkcs1-pem", "pkcs1-der", "sec1-pem", "sec1-der", "pkix-pem", "pkix-der", "openssh"} {
		t.Run(target, func(t *testing.T) {
			algorithm := "p256"
			if strings.HasPrefix(target, "pkcs1-") {
				algorithm = "rsa2048"
			}
			input := filepath.Join(t.TempDir(), "input.pem")
			if _, err := executeRoot(t, "key", "generate", algorithm, "--output", input); err != nil {
				t.Fatal(err)
			}
			public := strings.HasPrefix(target, "pkix-") || target == "openssh"
			for _, scenario := range []string{"new", "secure", "insecure", "override"} {
				t.Run(scenario, func(t *testing.T) {
					if runtime.GOOS == "windows" && scenario == "insecure" {
						t.Skip("POSIX permission bits do not configure Windows DACLs")
					}
					output := filepath.Join(t.TempDir(), "output")
					prepareConversionOutput(t, output, scenario)
					args := []string{"key", "convert", "--to", target, "--input", input, "--output", output}
					if scenario == "override" {
						args = append(args, "--mode", "0640")
					}
					_, err := executeRoot(t, args...)
					rejected := scenario == "insecure" && !public
					unsupported := runtime.GOOS == "windows" && scenario == "override"
					switch {
					case unsupported:
						if !errors.Is(err, errOutputModeUnsupported) {
							t.Fatalf("error = %v, want unsupported output mode", err)
						}
					case rejected:
						if !errors.Is(err, securefile.ErrNotOwnerOnly) {
							t.Fatalf("error = %v, want owner-only rejection", err)
						}
					case err != nil:
						t.Fatal(err)
					}
					data, err := os.ReadFile(output)
					if err != nil {
						t.Fatal(err)
					}
					if rejected || unsupported {
						if string(data) != "preserve" {
							t.Fatal("rejected conversion modified destination")
						}
					} else {
						assertConvertedKey(t, data, target, public)
					}
					if !rejected && !unsupported && !public && scenario != "override" {
						file, err := securefile.OpenOrCreateOwnerOnly(output)
						if err != nil {
							t.Fatal(err)
						}
						if err := file.Close(); err != nil {
							t.Fatal(err)
						}
					}

					if runtime.GOOS != "windows" {
						want := os.FileMode(0o600)
						if scenario == "insecure" {
							want = 0o644
						}
						if scenario == "override" {
							want = 0o640
						}
						info, err := os.Stat(output)
						if err != nil {
							t.Fatal(err)
						}
						if info.Mode().Perm() != want {
							t.Fatalf("mode = %04o, want %04o", info.Mode().Perm(), want)
						}
					}
				})
			}
		})
	}
}

func prepareConversionOutput(t *testing.T, path, scenario string) {
	t.Helper()
	switch scenario {
	case "new":
		return
	case "secure":
		file, err := securefile.OpenOrCreateOwnerOnly(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteString("preserve"); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	default:
		if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func assertConvertedKey(t *testing.T, data []byte, target string, public bool) {
	t.Helper()
	if target == "openssh" {
		if _, _, _, _, err := ssh.ParseAuthorizedKey(data); err != nil {
			t.Fatal(err)
		}
		return
	}
	key, err := asym.ParseKey(data)
	if err != nil {
		t.Fatal(err)
	}
	if key.IsPrivate() == public {
		t.Fatal("converted key has wrong visibility")
	}
}
