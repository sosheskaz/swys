package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
	"github.com/sosheskaz/swys/cmd/internal/cli/encoding"
	"github.com/sosheskaz/swys/internal/contextio"
)

type httpBody struct {
	reader      io.Reader
	closeErr    error
	close       func() error
	getBody     func() (io.ReadCloser, error)
	contentType string
	length      int64
	closeOnce   sync.Once
}

func (body *httpBody) Read(buffer []byte) (int, error) {
	return body.reader.Read(buffer) //nolint:wrapcheck // preserve EOF and streaming reader error identities
}

// Close releases the body once, whether called by the transport or command cleanup.
func (body *httpBody) Close() error {
	body.closeOnce.Do(func() {
		if body.close != nil {
			body.closeErr = body.close()
		}
	})
	return body.closeErr
}

func httpHasBodySource(cmd *cobra.Command) bool {
	for _, name := range []string{"input", httpDataFlagName, httpFormatJSON, "form", "file"} {
		if cmd.Flags().Changed(name) {
			return true
		}
	}
	return false
}

func prepareHTTPBody(cmd *cobra.Command, options *httpOptions, method string) (*httpBody, error) {
	decoder, err := encoding.GetInputDecoder(options.inputEncoding)
	if err != nil {
		return nil, err
	}
	input := cmd.Flag("input").Value.String()
	if cmd.Flags().Changed("input") {
		return httpSourceBody(cmd.Context(), input, cmd.InOrStdin(), decoder, options.inputEncoding == httpEncodingRaw)
	}
	if cmd.Flags().Changed(httpDataFlagName) {
		return httpLiteralBody(options.data, decoder, options.inputEncoding == httpEncodingRaw), nil
	}
	if cmd.Flags().Changed(httpFormatJSON) {
		return httpJSONBody(cmd.Context(), options, cmd.InOrStdin(), decoder)
	}
	if len(options.files) != 0 {
		return httpMultipartBody(options)
	}
	if len(options.forms) != 0 {
		return httpFormBody(options.forms)
	}
	if httpBodyUsesStdin(cmd, options, method) {
		return httpSourceBody(cmd.Context(), "-", cmd.InOrStdin(), decoder, options.inputEncoding == httpEncodingRaw)
	}
	return &httpBody{reader: http.NoBody}, nil
}

func httpBodyUsesStdin(cmd *cobra.Command, options *httpOptions, method string) bool {
	if cmd.Flags().Changed("input") {
		return cmd.Flag("input").Value.String() == "-"
	}
	if cmd.Flags().Changed("data") {
		return false
	}
	if cmd.Flags().Changed(httpFormatJSON) {
		return options.jsonData == "@-"
	}
	if len(options.files) != 0 || len(options.forms) != 0 {
		return false
	}
	return options.stdin == httpStdinAlways || options.stdin == httpStdinAuto &&
		method != http.MethodGet && method != http.MethodHead && !commandio.InputIsTerminal(cmd.InOrStdin())
}

func httpLiteralBody(value string, decoder encoding.InputDecoder, raw bool) *httpBody {
	body := &httpBody{reader: decoder(strings.NewReader(value)), length: -1}
	if raw {
		body.length = int64(len(value))
	}
	body.getBody = func() (io.ReadCloser, error) {
		return io.NopCloser(decoder(strings.NewReader(value))), nil
	}
	return body
}

func httpSourceBody(ctx context.Context, path string, stdin io.Reader, decoder encoding.InputDecoder, raw bool) (*httpBody, error) {
	if path != "-" {
		return httpFileBody(ctx, path, decoder, raw)
	}
	// Closing a blocking stdin does not wake a pending read, so the body reads
	// through a reader that also stops on cancellation.
	body := &httpBody{reader: decoder(contextio.NewReader(ctx, stdin)), length: -1}
	if closer, ok := stdin.(io.Closer); ok {
		// The HTTP transport must be able to interrupt a blocked stdin read
		// when the peer responds early or the request is canceled.
		body.close = closer.Close
	}
	return body, nil
}

// openHTTPBodyFile opens the body path without blocking a signal, since a FIFO
// with no peer blocks the open itself.
func openHTTPBodyFile(ctx context.Context, path string) (*os.File, error) {
	return contextio.OpenFile(ctx, func() (*os.File, error) {
		file, err := os.Open(path) //nolint:gosec // opening an explicitly selected HTTP body is intended
		if err != nil {
			return nil, fmt.Errorf("open HTTP body: %w", err)
		}
		return file, nil
	})
}

func httpFileBody(ctx context.Context, path string, decoder encoding.InputDecoder, raw bool) (*httpBody, error) {
	file, err := openHTTPBodyFile(ctx, path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("stat HTTP body: %w", err), file.Close())
	}
	if info.IsDir() {
		return nil, errors.Join(fmt.Errorf("%w: HTTP body is a directory", ErrInvalidFlags), file.Close())
	}
	owned, err := contextio.NewOwnedFileReader(ctx, file)
	if err != nil {
		return nil, fmt.Errorf("prepare HTTP body: %w", err)
	}
	body := &httpBody{reader: decoder(owned), close: owned.Close, length: -1}
	if info.Mode().IsRegular() {
		if raw {
			body.length = info.Size()
		}
		body.getBody = func() (io.ReadCloser, error) {
			return httpFileBody(ctx, path, decoder, raw)
		}
	}
	return body, nil
}

func httpJSONBody(ctx context.Context, options *httpOptions, stdin io.Reader, decoder encoding.InputDecoder) (*httpBody, error) {
	var body *httpBody
	if path, exists := strings.CutPrefix(options.jsonData, "@"); exists {
		var err error
		body, err = httpSourceBody(ctx, path, stdin, decoder, options.inputEncoding == httpEncodingRaw)
		if err != nil {
			return nil, err
		}
	} else {
		body = httpLiteralBody(options.jsonData, decoder, options.inputEncoding == httpEncodingRaw)
	}
	body.contentType = httpMediaTypeJSON
	return body, nil
}

func httpFormBody(fields []string) (*httpBody, error) {
	values := make(url.Values)
	for _, field := range fields {
		name, value, err := httpField(field)
		if err != nil {
			return nil, err
		}
		values.Add(name, value)
	}
	body := httpLiteralBody(values.Encode(), func(input io.Reader) io.Reader { return input }, true)
	body.contentType = "application/x-www-form-urlencoded"
	return body, nil
}

func httpField(field string) (string, string, error) {
	name, value, exists := strings.Cut(field, "=")
	if !exists || name == "" || !httpHeaderValue(name) || strings.ContainsAny(name, "\r\n") {
		return "", "", fmt.Errorf("%w: expected a nonempty field name followed by =value", ErrInvalidFlags)
	}
	return name, value, nil
}

func httpBodyPaths(cmd *cobra.Command, options *httpOptions) ([]string, error) {
	paths := make([]string, 0, len(options.files)+1)
	if input := cmd.Flag("input").Value.String(); input != "" && input != "-" {
		paths = append(paths, input)
	}
	jsonPath, isJSONPath := strings.CutPrefix(options.jsonData, "@")
	if cmd.Flags().Changed(httpFormatJSON) && isJSONPath {
		if jsonPath == "" {
			return nil, fmt.Errorf("%w: --json @ requires a path or -", ErrInvalidFlags)
		}
		if jsonPath != "-" {
			paths = append(paths, jsonPath)
		}
	}
	for _, field := range options.forms {
		if _, _, err := httpField(field); err != nil {
			return nil, err
		}
	}
	for _, field := range options.files {
		_, path, err := httpField(field)
		if err != nil {
			return nil, err
		}
		if path == "" || path == "-" || !httpHeaderValue(filepath.Base(path)) {
			return nil, fmt.Errorf("%w: --file requires a file path with a valid filename", ErrInvalidFlags)
		}
		paths = append(paths, path)
	}
	return paths, nil
}

type httpUpload struct {
	file *os.File
	name string
}

func httpMultipartBody(options *httpOptions) (*httpBody, error) {
	return httpMultipartBodyWithBoundary(options, "")
}

func httpMultipartBodyWithBoundary(options *httpOptions, boundary string) (*httpBody, error) {
	uploads := make([]httpUpload, 0, len(options.files))
	for _, field := range options.files {
		name, path, err := httpField(field)
		if err != nil {
			return nil, errors.Join(err, closeHTTPUploads(uploads))
		}
		file, err := os.Open(path) //nolint:gosec // opening an explicitly selected upload is intended
		if err != nil {
			return nil, errors.Join(fmt.Errorf("open HTTP upload: %w", err), closeHTTPUploads(uploads))
		}
		uploads = append(uploads, httpUpload{file: file, name: name})
		info, err := file.Stat()
		if err != nil {
			return nil, errors.Join(fmt.Errorf("stat HTTP upload: %w", err), closeHTTPUploads(uploads))
		}
		if !info.Mode().IsRegular() {
			return nil, errors.Join(fmt.Errorf("%w: multipart uploads require regular files", ErrInvalidFlags), closeHTTPUploads(uploads))
		}
	}
	reader, writer := io.Pipe()
	form := multipart.NewWriter(writer)
	if boundary != "" {
		if err := form.SetBoundary(boundary); err != nil {
			return nil, errors.Join(fmt.Errorf("set multipart boundary: %w", err), reader.Close(), writer.Close(), closeHTTPUploads(uploads))
		}
	}
	var start sync.Once
	var done sync.WaitGroup
	// Defer starting the producer until the transport reads the body; a flag
	// or output-file error before the request must not leave a goroutine behind.
	read := &httpMultipartReader{reader: reader, start: func() {
		start.Do(func() {
			done.Add(1)
			go func() {
				defer done.Done()
				err := writeHTTPMultipart(form, options.forms, uploads)
				_ = writer.CloseWithError(err)
			}()
		})
	}}
	return &httpBody{
		reader: read, length: -1, contentType: form.FormDataContentType(),
		getBody: func() (io.ReadCloser, error) {
			return httpMultipartBodyWithBoundary(options, form.Boundary())
		},
		close: func() error {
			// Serialize producer creation with cleanup before waiting for it.
			start.Do(func() {})
			// Closing both ends also covers a request rejected before its first read.
			err := errors.Join(reader.Close(), writer.Close(), closeHTTPUploads(uploads))
			done.Wait()
			return err
		},
	}, nil
}

type httpMultipartReader struct {
	reader *io.PipeReader
	start  func()
}

func (reader *httpMultipartReader) Read(buffer []byte) (int, error) {
	reader.start()
	return reader.reader.Read(buffer) //nolint:wrapcheck // preserve streaming EOF/error identities
}

func writeHTTPMultipart(writer *multipart.Writer, fields []string, uploads []httpUpload) error {
	for _, field := range fields {
		name, value, err := httpField(field)
		if err != nil {
			return err
		}
		if err := writer.WriteField(name, value); err != nil {
			return fmt.Errorf("write multipart field: %w", err)
		}
	}
	for _, upload := range uploads {
		part, err := writer.CreateFormFile(upload.name, filepath.Base(upload.file.Name()))
		if err != nil {
			return fmt.Errorf("create multipart file: %w", err)
		}
		if _, err := io.Copy(part, upload.file); err != nil {
			return fmt.Errorf("write multipart file: %w", err)
		}
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish multipart body: %w", err)
	}
	return nil
}

func closeHTTPUploads(uploads []httpUpload) error {
	var result error
	for _, upload := range uploads {
		result = errors.Join(result, upload.file.Close())
	}
	return result
}
