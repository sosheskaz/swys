package cmd

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkHTTPStreaming(b *testing.B) {
	for _, size := range []int{64 << 10, 8 << 20} {
		payload := bytes.Repeat([]byte("x"), size)

		b.Run(byteCountLabel(size)+" response", func(b *testing.B) {
			server := newHTTPBenchmarkResponseServer(b, payload)
			defer server.Close()

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				benchmarkHTTPCommand(b, "http", server.URL)
			}
		})

		b.Run(byteCountLabel(size)+" JSON response", func(b *testing.B) {
			server := newHTTPBenchmarkResponseServer(b, payload)
			defer server.Close()

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				benchmarkHTTPCommand(b, "http", server.URL, "--format", "json")
			}
		})

		b.Run(byteCountLabel(size)+" upload", func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "upload.bin")
			if err := os.WriteFile(path, payload, 0o600); err != nil {
				b.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if _, err := io.Copy(io.Discard, request.Body); err != nil {
					b.Errorf("read benchmark upload: %v", err)
				}
				writer.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				benchmarkHTTPCommand(b, "http", "-X", "POST", server.URL, "--input", path)
			}
		})

		b.Run(byteCountLabel(size)+" multipart upload", func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "upload.bin")
			if err := os.WriteFile(path, payload, 0o600); err != nil {
				b.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if _, err := io.Copy(io.Discard, request.Body); err != nil {
					b.Errorf("read benchmark multipart upload: %v", err)
				}
				writer.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				benchmarkHTTPCommand(b, "http", "-X", "POST", server.URL, "--file", "attachment="+path)
			}
		})
	}
}

func BenchmarkHTTPZstdStreaming(b *testing.B) {
	for _, size := range []int{64 << 10, 8 << 20, 64 << 20} {
		payload := bytes.Repeat([]byte("x"), size)
		compressed := encodeHTTPZstdTestBody(b, payload, 1<<20)
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Encoding", "zstd")
			if _, err := writer.Write(compressed); err != nil {
				b.Errorf("write benchmark response: %v", err)
			}
		}))
		b.Cleanup(server.Close)

		b.Run(byteCountLabel(size), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				benchmarkHTTPCommand(b, "http", server.URL)
			}
		})
	}
}

func newHTTPBenchmarkResponseServer(b *testing.B, payload []byte) *httptest.Server {
	b.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if _, err := writer.Write(payload); err != nil {
			b.Errorf("write benchmark response: %v", err)
		}
	}))
}

func benchmarkHTTPCommand(b *testing.B, args ...string) {
	b.Helper()
	root := newRootCmd()
	root.SetIn(bytes.NewReader(nil))
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs(args)
	if err := executeCommand(root); err != nil {
		b.Fatal(err)
	}
}

func byteCountLabel(size int) string {
	if size%(1<<20) == 0 {
		return fmt.Sprintf("%dMiB", size/(1<<20))
	}
	return fmt.Sprintf("%dKiB", size/(1<<10))
}
