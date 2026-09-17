package cmd

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

const (
	httpAcceptEncoding = "gzip, br, zstd"
	httpZstdMaxWindow  = 8 << 20
)

func httpCompressionTransport(transport http.RoundTripper) http.RoundTripper {
	return httpRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		negotiated := shouldNegotiateHTTPCompression(request)
		if negotiated {
			request = request.Clone(request.Context())
			request.Header.Set("Accept-Encoding", httpAcceptEncoding)
		}

		response, err := transport.RoundTrip(request)
		if err != nil {
			return response, err //nolint:wrapcheck // Preserve transport error interfaces used by http.Client.
		}
		if response == nil || !negotiated {
			return response, nil
		}
		codings, supported := supportedHTTPContentCodings(response.Header.Values("Content-Encoding"))
		if !supported || len(codings) == 0 || response.Body == nil || !httpResponseMayHaveBody(response.StatusCode) {
			return response, nil
		}
		response.Body = &httpDecodedBody{source: response.Body, codings: codings}
		response.Header.Del("Content-Encoding")
		response.Header.Del("Content-Length")
		response.ContentLength = -1
		response.Uncompressed = true
		return response, nil
	})
}

func httpResponseMayHaveBody(statusCode int) bool {
	return statusCode >= 200 && statusCode != http.StatusNoContent && statusCode != http.StatusResetContent &&
		statusCode != http.StatusNotModified
}

func shouldNegotiateHTTPCompression(request *http.Request) bool {
	return request != nil && request.Method != http.MethodHead && request.Header.Get("Range") == "" &&
		!httpHeaderSupplied(request.Header, "Accept-Encoding")
}

func httpHeaderSupplied(header http.Header, name string) bool {
	for field := range header {
		if strings.EqualFold(field, name) {
			return true
		}
	}
	return false
}

func supportedHTTPContentCodings(values []string) ([]string, bool) {
	var codings []string
	for _, value := range values {
		for coding := range strings.SplitSeq(value, ",") {
			coding = strings.ToLower(strings.TrimSpace(coding))
			switch coding {
			case httpCodingGzip, httpCodingBrotli, httpCodingZstd:
				codings = append(codings, coding)
			case "identity":
			case "":
				return nil, false
			default:
				return nil, false
			}
		}
	}
	return codings, true
}

type httpDecodedBody struct {
	source   io.ReadCloser
	reader   io.Reader
	initErr  error
	closeErr error
	codings  []string
	closers  []io.Closer

	initialize sync.Once
	close      sync.Once
}

func (body *httpDecodedBody) Read(buffer []byte) (int, error) {
	body.initialize.Do(body.initializeReader)
	if body.initErr != nil {
		return 0, body.initErr
	}
	count, err := body.reader.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		err = fmt.Errorf("decode HTTP response body (%s): %w", strings.Join(body.codings, ", "), err)
	}
	return count, err
}

// Close releases any initialized decoders and closes the encoded response body.
func (body *httpDecodedBody) Close() error {
	body.close.Do(func() {
		for index := len(body.closers) - 1; index >= 0; index-- {
			body.closeErr = errors.Join(body.closeErr, body.closers[index].Close())
		}
		body.closeErr = errors.Join(body.closeErr, body.source.Close())
	})
	return body.closeErr
}

func (body *httpDecodedBody) initializeReader() {
	reader := io.Reader(body.source)
	for index := len(body.codings) - 1; index >= 0; index-- {
		coding := body.codings[index]
		switch coding {
		case httpCodingGzip:
			decoder, err := gzip.NewReader(reader)
			if err != nil {
				body.initErr = fmt.Errorf("decode HTTP response body (%s): %w", strings.Join(body.codings, ", "), err)
				return
			}
			body.closers = append(body.closers, decoder)
			reader = decoder
		case httpCodingBrotli:
			reader = brotli.NewReader(reader)
		case httpCodingZstd:
			decoder, err := zstd.NewReader(
				reader,
				zstd.WithDecoderConcurrency(1),
				zstd.WithDecoderLowmem(true),
				zstd.WithDecodeBuffersBelow(0),
				// RFC 9659 limits the zstd HTTP content-coding window to 8 MiB.
				zstd.WithDecoderMaxWindow(httpZstdMaxWindow),
			)
			if err != nil {
				body.initErr = fmt.Errorf("decode HTTP response body (%s): %w", strings.Join(body.codings, ", "), err)
				return
			}
			body.closers = append(body.closers, decoder.IOReadCloser())
			reader = decoder
		}
	}
	body.reader = reader
}
