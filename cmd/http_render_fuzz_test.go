package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"
	"testing/iotest"
)

var (
	errFuzzHTTPBody    = errors.New("fuzz HTTP body read failure")
	errFuzzHTTPOutput  = errors.New("fuzz HTTP output failure")
	errFuzzHTTPRequest = errors.New("fuzz HTTP request failure")
)

func FuzzWriteHTTPJSONResponse(f *testing.F) {
	f.Add([]byte{}, uint16(0), false, false, false, false, uint8(0))
	f.Add([]byte("plain response"), uint16(5), false, false, false, false, uint8(1))
	f.Add([]byte{0x00, 0x1b, 0x7f, 0x80, 0xff}, uint16(3), true, false, false, false, uint8(2))
	f.Add([]byte("no response"), uint16(0), false, true, true, false, uint8(3))
	for failureCall := range uint8(8) {
		f.Add([]byte("output failure"), uint16(4), true, false, true, true, failureCall)
	}

	f.Fuzz(func(
		t *testing.T,
		data []byte,
		fuzzFailureOffset uint16,
		bodyFail, nilResponse, requestFail, outputFail bool,
		outputFailureCall uint8,
	) {
		if len(data) > 8<<10 {
			t.Skip()
		}
		bodyData := data
		if bodyFail {
			offset := int(fuzzFailureOffset) % (len(data) + 1)
			bodyData = data[:offset]
		}
		request := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: "example.test", Path: "/fuzz"}}
		var requestErr error
		if requestFail {
			requestErr = errFuzzHTTPRequest
		}
		newResponse := func() *http.Response {
			if nilResponse {
				return nil
			}
			reader := iotest.OneByteReader(bytes.NewReader(bodyData))
			if bodyFail {
				reader = io.MultiReader(reader, iotest.ErrReader(errFuzzHTTPBody))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Proto:      "HTTP/1.1",
				Header:     http.Header{"X-Test": []string{"fuzz"}},
				Body:       io.NopCloser(reader),
			}
		}

		baseline := &fuzzHTTPRecordingWriter{}
		baselineResponse := newResponse()
		err := writeHTTPJSONResponse(baseline, request, baselineResponse, requestErr, nil)
		if baselineResponse != nil {
			if closeErr := baselineResponse.Body.Close(); closeErr != nil {
				t.Fatalf("close baseline fuzz HTTP response body: %v", closeErr)
			}
		}
		if outputFail {
			assertFuzzHTTPOutputFailure(t, request, newResponse, requestErr, outputFailureCall, baseline.calls)
			return
		}

		if requestFail && !errors.Is(err, errFuzzHTTPRequest) {
			t.Fatalf("response error = %v, want request failure", err)
		}
		if bodyFail && !nilResponse && !errors.Is(err, errFuzzHTTPBody) {
			t.Fatalf("response error = %v, want body read failure", err)
		}
		if !requestFail && (!bodyFail || nilResponse) && err != nil {
			t.Fatalf("response error = %v, want nil", err)
		}

		var envelope struct {
			Body         string `json:"body"`
			BodyEncoding string `json:"body_encoding"`
			Error        string `json:"error"`
			Complete     bool   `json:"complete"`
		}
		if err := json.Unmarshal(baseline.output, &envelope); err != nil {
			t.Fatalf("response is not valid JSON: %v; output %q", err, baseline.output)
		}
		decoded, err := base64.StdEncoding.DecodeString(envelope.Body)
		if err != nil {
			t.Fatalf("response body is not valid base64: %v", err)
		}
		wantBody := bodyData
		if nilResponse {
			wantBody = nil
		}
		if !bytes.Equal(decoded, wantBody) {
			t.Fatalf("response body changed: got %x, want %x", decoded, wantBody)
		}
		wantComplete := !nilResponse && !bodyFail
		wantError := requestFail || bodyFail && !nilResponse
		if envelope.BodyEncoding != "base64" || envelope.Complete != wantComplete || (envelope.Error != "") != wantError {
			t.Fatalf("response completion metadata = %+v, want complete=%t error=%t", envelope, wantComplete, wantError)
		}
	})
}

func assertFuzzHTTPOutputFailure(
	t *testing.T,
	request *http.Request,
	newResponse func() *http.Response,
	requestErr error,
	failureCall uint8,
	baselineCalls int,
) {
	t.Helper()
	if baselineCalls == 0 {
		t.Fatal("HTTP JSON response made no output calls")
	}
	output := &fuzzHTTPFailOnceWriter{failAt: int(failureCall) % baselineCalls}
	response := newResponse()
	err := writeHTTPJSONResponse(output, request, response, requestErr, nil)
	if response != nil {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Fatalf("close failing-writer fuzz HTTP response body: %v", closeErr)
		}
	}
	if !errors.Is(err, errFuzzHTTPOutput) {
		t.Fatalf("response error = %v, want output failure on call %d of %d", err, output.failAt, baselineCalls)
	}
}

type fuzzHTTPRecordingWriter struct {
	output []byte
	calls  int
}

func (writer *fuzzHTTPRecordingWriter) Write(buffer []byte) (int, error) {
	writer.calls++
	writer.output = append(writer.output, buffer...)
	return len(buffer), nil
}

type fuzzHTTPFailOnceWriter struct {
	output []byte
	calls  int
	failAt int
}

func (writer *fuzzHTTPFailOnceWriter) Write(buffer []byte) (int, error) {
	call := writer.calls
	writer.calls++
	if call == writer.failAt {
		return 0, errFuzzHTTPOutput
	}
	writer.output = append(writer.output, buffer...)
	return len(buffer), nil
}
