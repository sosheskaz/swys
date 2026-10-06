package http

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/internal/asym"
)

func writeHTTPResponse(cmd *cobra.Command, options *httpOptions, request *http.Request, response *http.Response, requestErr error, trace *httpTrace) error {
	selected := selectHTTPOutput(options.selection, request, response)
	var renderErr error
	switch effectiveHTTPFormat(options) {
	case httpFormatJSON:
		renderErr = writeHTTPJSONSelection(cmd.OutOrStdout(), selected, requestErr)
	default:
		if selected.response != nil {
			if selected.includeMetadata {
				renderErr = writeHTTPHead(cmd.OutOrStdout(), selected.response)
			}
			if (selected.request == nil || selected.request.Method != http.MethodHead) && renderErr == nil {
				_, renderErr = io.Copy(cmd.OutOrStdout(), selected.response.Body)
			}
		}
	}
	trace.finish()
	if options.trace {
		renderErr = errors.Join(renderErr, trace.writeText(cmd.ErrOrStderr()))
	}
	return errors.Join(requestErr, renderErr)
}

type httpSelectedOutput struct {
	request         *http.Request
	response        *http.Response
	includeMetadata bool
}

func selectHTTPOutput(selection string, request *http.Request, response *http.Response) httpSelectedOutput {
	return httpSelectedOutput{request: request, response: response, includeMetadata: selection == httpSelectResponse}
}

func writeHTTPHead(output io.Writer, response *http.Response) error {
	if _, err := fmt.Fprintf(output, "%s %s\n", asym.EscapeDiagnosticValue(response.Proto), asym.EscapeDiagnosticValue(response.Status)); err != nil {
		return fmt.Errorf("write HTTP status: %w", err)
	}
	for name, values := range response.Header {
		for _, value := range values {
			if _, err := fmt.Fprintf(output, "%s: %s\n", asym.EscapeDiagnosticValue(name), asym.EscapeDiagnosticValue(value)); err != nil {
				return fmt.Errorf("write HTTP header: %w", err)
			}
		}
	}
	_, err := io.WriteString(output, "\n")
	if err != nil {
		return fmt.Errorf("write HTTP header separator: %w", err)
	}
	return nil
}

func writeHTTPJSONSelection(output io.Writer, selected httpSelectedOutput, requestErr error) error {
	response := selected.response
	prefix, err := httpJSONPrefix(selected)
	if err != nil {
		return errors.Join(requestErr, err)
	}
	prefix = prefix[:len(prefix)-1]
	if _, err = output.Write(prefix); err != nil {
		return errors.Join(requestErr, err)
	}
	bodyField := `,"body":"`
	if !selected.includeMetadata {
		bodyField = `"body":"`
	}
	if _, err = io.WriteString(output, bodyField); err != nil {
		return errors.Join(requestErr, err)
	}

	var copyErr, closeErr error
	if response != nil {
		encoder := base64.NewEncoder(base64.StdEncoding, output)
		_, copyErr = io.Copy(encoder, response.Body)
		closeErr = encoder.Close()
	}
	allErr := errors.Join(requestErr, copyErr, closeErr)
	suffix := struct { //nolint:govet // Field order defines the documented JSON envelope order.
		BodyEncoding string `json:"body_encoding"`
		Complete     bool   `json:"complete"`
		Error        string `json:"error,omitempty"`
	}{BodyEncoding: "base64", Complete: response != nil && copyErr == nil && closeErr == nil}
	if allErr != nil {
		suffix.Error = allErr.Error()
	}
	encodedSuffix, marshalErr := json.Marshal(suffix)
	if marshalErr != nil {
		return errors.Join(allErr, marshalErr)
	}
	encodedSuffix = encodedSuffix[1:]
	if _, err := io.WriteString(output, `",`); err != nil {
		return errors.Join(allErr, err)
	}
	_, writeErr := output.Write(encodedSuffix)
	return errors.Join(allErr, writeErr)
}

func httpJSONPrefix(selected httpSelectedOutput) ([]byte, error) {
	if !selected.includeMetadata {
		return []byte{'{', '}'}, nil
	}
	metadata := struct { //nolint:govet // Field order defines the documented JSON envelope order.
		Method     string      `json:"method"`
		URL        string      `json:"url"`
		StatusCode int         `json:"status_code"`
		Status     string      `json:"status"`
		Protocol   string      `json:"protocol"`
		Headers    http.Header `json:"headers"`
	}{Headers: http.Header{}}
	if selected.request != nil {
		metadata.Method, metadata.URL = selected.request.Method, selected.request.URL.Redacted()
	}
	if response := selected.response; response != nil {
		if response.Request != nil {
			metadata.Method, metadata.URL = response.Request.Method, response.Request.URL.Redacted()
		}
		metadata.StatusCode, metadata.Status, metadata.Protocol, metadata.Headers = response.StatusCode, response.Status, response.Proto, response.Header
	}
	prefix, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal HTTP response metadata: %w", err)
	}
	return prefix, nil
}
