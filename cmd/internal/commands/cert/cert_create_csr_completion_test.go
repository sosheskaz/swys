package cert_test

import "testing"

func TestCertCreateCSRCompletionRespectsSourceMode(t *testing.T) {
	t.Parallel()

	t.Run("existing key hides CSR", func(t *testing.T) {
		t.Parallel()
		values, _ := executeCertificateCompletion(t, "cert", "create", "--key", "key.pem", "--")
		if completionContainsFlag(values, "--csr") {
			t.Fatalf("completion after --key contains conflicting --csr: %q", values)
		}
		for _, compatible := range []string{"--ca", "--issuer-cert", "--issuer-key"} {
			if !completionContainsFlag(values, compatible) {
				t.Fatalf("completion after --key hides compatible %s: %q", compatible, values)
			}
		}
	})

	t.Run("CSR hides key and CA", func(t *testing.T) {
		t.Parallel()
		values, _ := executeCertificateCompletion(t, "cert", "create", "--csr", "request.pem", "--")
		for _, conflict := range []string{"--key", "--ca"} {
			if completionContainsFlag(values, conflict) {
				t.Fatalf("completion after --csr contains conflicting %s: %q", conflict, values)
			}
		}
		for _, required := range []string{"--issuer-cert", "--issuer-key"} {
			if !completionContainsFlag(values, required) {
				t.Fatalf("completion after --csr hides required %s: %q", required, values)
			}
		}
	})

	t.Run("issuer pair leaves both source choices", func(t *testing.T) {
		t.Parallel()
		values, _ := executeCertificateCompletion(
			t,
			"cert", "create", "--issuer-cert", "ca.pem", "--issuer-key", "ca-key.pem", "--",
		)
		for _, choice := range []string{"--key", "--csr"} {
			if !completionContainsFlag(values, choice) {
				t.Fatalf("completion after issuer pair hides source choice %s: %q", choice, values)
			}
		}
	})
}
