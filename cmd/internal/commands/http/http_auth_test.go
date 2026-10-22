package http_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/cli/certinput"
)

func TestHTTPAuthValidationPrecedesIO(t *testing.T) {
	t.Parallel()
	const secret = "validation-secret"
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	t.Cleanup(server.Close)
	cleartextURL := server.URL
	userinfoURL := strings.Replace(server.URL, "http://", "http://user:"+secret+"@", 1)
	for _, test := range []struct {
		name  string
		url   string
		want  string
		flags []string
	}{
		{name: "two sources", flags: []string{"--auth-bearer", "a", "--auth-basic", "u:p", "--insecure-cleartext-auth"}, want: "choose one of"},
		{
			name: "empty Authorization header", want: "Authorization --header",
			flags: []string{"--auth-bearer", "a", "--insecure-cleartext-auth", "-H", "Authorization:"},
		},
		{
			name: "lowercase Authorization header", want: "Authorization --header",
			flags: []string{"--auth-bearer", "a", "--insecure-cleartext-auth", "-H", "authorization: x"},
		},
		{name: "URL credentials", url: userinfoURL, flags: []string{"--auth-bearer", "a", "--insecure-cleartext-auth"}, want: "URL credentials"},
		{name: "cleartext without opt-in", flags: []string{"--auth-bearer", secret}, want: "without TLS requires --insecure-cleartext-auth"},
		{name: "cleartext opt-in without credential", flags: []string{"--insecure-cleartext-auth"}, want: "requires an --auth-* credential"},
		{name: "payload owns stdin", flags: []string{"--auth-bearer-file", "-", "--insecure", "--input", "-"}, want: "--auth-bearer-file and payload"},
		{
			name: "TLS owns stdin", want: "--auth-bearer-file and --ca",
			flags: []string{"--auth-bearer-file", "-", "--insecure-cleartext-auth", "--ca", "-", "--stdin", "never"},
		},
		{name: "malformed token", flags: []string{"--auth-bearer", "Bearer " + secret, "--insecure-cleartext-auth"}, want: "Bearer scheme is added"},
		{name: "unset variable", flags: []string{"--auth-bearer-env", "SWYS_TEST_UNSET_TOKEN", "--insecure-cleartext-auth"}, want: "is not set"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := &countingReader{source: strings.NewReader("not credentials or payload")}
			output := filepath.Join(t.TempDir(), "output")
			require.NoError(t, os.WriteFile(output, []byte("preserved"), 0o600))
			url := test.url
			if url == "" {
				url = cleartextURL
			}
			args := append([]string{"http", "-X", "POST", url, "--output", output}, test.flags...)
			stdout, stderr, err := executeHTTPStreamsWithInput(t, input, args...)
			require.ErrorIs(t, err, errInvalidHTTPFlags)
			assert.Contains(t, err.Error(), test.want)
			assert.NotContains(t, err.Error()+stderr, secret, "diagnostics expose the credential")
			assert.Zero(t, input.reads.Load())
			assert.Empty(t, stdout)
			data, readErr := os.ReadFile(output)
			require.NoError(t, readErr)
			assert.Equal(t, "preserved", string(data))
			assert.Zero(t, requests.Load(), "validation reached HTTP")
		})
	}
}

func TestHTTPAuthFileCannotBeOutput(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte("token\n"), 0o600))
	_, _, err := executeRootStreams(t, "http", "https://127.0.0.1:1/", "--auth-bearer-file", path, "--output", path)
	require.ErrorIs(t, err, certinput.ErrPathCollision)
	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "token\n", string(data), "the credential file was overwritten")
}

func TestHTTPAuthReadsStdinWhenPayloadDoesNot(t *testing.T) {
	t.Parallel()
	server, caPath, received := startHTTPAuthServer(t)
	_, _, err := executeHTTPStreamsWithInput(t, strings.NewReader("stdin-token\n"),
		"http", server.URL, "--ca", caPath, "--auth-bearer-file", "-")
	require.NoError(t, err)
	assert.Equal(t, []string{"Bearer stdin-token"}, <-received)
}

func TestHTTPAuthUmbrellaPermitsCleartext(t *testing.T) {
	t.Parallel()
	received := make(chan []string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		received <- request.Header.Values("Authorization")
	}))
	t.Cleanup(server.Close)
	_, _, err := executeRootStreams(t, "http", server.URL, "--auth-basic", "user:pass", "--insecure")
	require.NoError(t, err)
	assert.Equal(t, []string{"Basic dXNlcjpwYXNz"}, <-received)
}

func TestHTTPAuthCleartextOptInIsInertOverTLS(t *testing.T) {
	t.Parallel()
	server, caPath, received := startHTTPAuthServer(t)
	_, _, err := executeRootStreams(t, "http", server.URL, "--ca", caPath, "--auth-bearer", "t", "--insecure-cleartext-auth")
	require.NoError(t, err)
	assert.Equal(t, []string{"Bearer t"}, <-received)
}

func TestHTTPAuthRedirectsDropCredentialsAfterLeavingTLS(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		path string
		want []httpAuthHop
	}{
		{
			name: "same origin keeps credentials", path: "/same-origin",
			want: []httpAuthHop{{"/same-origin", []string{"Bearer t"}}, {"/final", []string{"Bearer t"}}},
		},
		{
			name: "downgrade drops credentials for the rest of the chain", path: "/downgrade",
			want: []httpAuthHop{{"/downgrade", []string{"Bearer t"}}, {"/plain", nil}, {"/back", nil}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			secureURL, caPath, hops := startHTTPRedirectChain(t)
			_, _, err := executeRootStreams(t, "http", secureURL+test.path, "--ca", caPath, "--auth-bearer", "t")
			require.NoError(t, err)
			var got []httpAuthHop
			for range test.want {
				got = append(got, <-hops)
			}
			assert.Equal(t, test.want, got)
		})
	}
}

type httpAuthHop struct {
	path          string
	authorization []string
}

// startHTTPRedirectChain links a TLS server and a cleartext server on 127.0.0.1.
// The shared hostname means net/http alone would keep the Authorization header.
func startHTTPRedirectChain(t *testing.T) (string, string, <-chan httpAuthHop) {
	t.Helper()
	hops := make(chan httpAuthHop, 8)
	record := func(request *http.Request) {
		hops <- httpAuthHop{path: request.URL.Path, authorization: request.Header.Values("Authorization")}
	}
	var secureURL atomic.Pointer[string]
	cleartext := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		record(request)
		http.Redirect(writer, request, *secureURL.Load()+"/back", http.StatusFound)
	}))
	t.Cleanup(cleartext.Close)
	secure, caPath := startTrustedHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		record(request)
		switch request.URL.Path {
		case "/downgrade":
			http.Redirect(writer, request, cleartext.URL+"/plain", http.StatusFound)
		case "/same-origin":
			http.Redirect(writer, request, "/final", http.StatusFound)
		}
	}))
	secureURL.Store(&secure.URL)
	return secure.URL, caPath, hops
}

func TestHTTPAuthStaysOutOfOutputAndDiagnostics(t *testing.T) {
	t.Parallel()
	const secret = "diagnostic-secret"
	server, caPath, received := startHTTPAuthServer(t)
	stdout, stderr, err := executeRootStreams(t, "http", server.URL, "--ca", caPath, "--auth-bearer", secret,
		"--trace", "--select", "response", "--format", "json")
	require.NoError(t, err)
	assert.Equal(t, []string{"Bearer " + secret}, <-received)
	assert.NotContains(t, stdout, secret)
	assert.NotContains(t, stderr, secret)
}

func TestHTTPInsecureNoVerify(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeHTTPTestString(t, writer, "unverified")
	}))
	t.Cleanup(server.Close)
	caPath := filepath.Join(t.TempDir(), "unused-ca.pem")
	for _, flag := range []string{"--insecure", "--insecure-no-verify"} {
		t.Run(flag, func(t *testing.T) {
			t.Parallel()
			stdout, _, err := executeRootStreams(t, "http", server.URL, flag)
			require.NoError(t, err)
			assert.Equal(t, "unverified", stdout)

			_, _, err = executeRootStreams(t, "http", server.URL, flag, "--ca", caPath)
			require.ErrorIs(t, err, errInvalidHTTPFlags)
			assert.Contains(t, err.Error(), flag, "the conflict names the flag the user passed")
		})
	}
}
