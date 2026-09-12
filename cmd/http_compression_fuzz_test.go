package cmd

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

var errFuzzDecodedBodyTooLarge = errors.New("decoded body exceeds fuzz limit")

func FuzzHTTPDecodedBody(f *testing.F) {
	for selector := range uint8(7) {
		f.Add([]byte("compressed response\x00\xff"), selector, uint8(0), uint16(0), uint8(7))
	}
	f.Add([]byte{}, uint8(0), uint8(1), uint16(0), uint8(1))
	f.Add([]byte("runtime decoder error"), uint8(0), uint8(1), uint16(12), uint8(7))
	f.Add(bytes.Repeat([]byte("compressible"), 32), uint8(6), uint8(2), uint16(17), uint8(31))

	chains := [][]string{
		{"gzip"},
		{"br"},
		{"zstd"},
		{"gzip", "br"},
		{"br", "zstd"},
		{"zstd", "gzip"},
		{"gzip", "br", "zstd"},
	}
	f.Fuzz(func(t *testing.T, payload []byte, selector, mutation uint8, mutationIndex uint16, readWidth uint8) {
		if len(payload) > 8<<10 {
			t.Skip()
		}
		codings := chains[int(selector)%len(chains)]
		wire := encodeHTTPTestBody(t, payload, codings...)
		switch mutation % 4 {
		case 1:
			if len(wire) == 0 {
				t.Fatal("encoded body is empty")
			}
			wire = wire[:int(mutationIndex)%len(wire)]
		case 2:
			if len(wire) != 0 {
				wire = bytes.Clone(wire)
				wire[int(mutationIndex)%len(wire)] ^= 0x80
			}
		case 3:
			wire = append(bytes.Clone(wire), byte(mutationIndex), byte(mutationIndex>>8))
		}

		width := int(readWidth)%64 + 1
		want, wantErr, wantCloseErr := decodeHTTPBodyReference(wire, codings, width)
		source := &countingReadCloser{Reader: bytes.NewReader(wire)}
		body := &httpDecodedBody{source: source, codings: codings}
		got, err := readFuzzBody(body, width, 128<<10)
		closeErr := body.Close()
		secondCloseErr := body.Close()
		if (closeErr == nil) != (secondCloseErr == nil) || closeErr != nil && closeErr.Error() != secondCloseErr.Error() {
			t.Fatalf("decoded body close was not idempotent: first %v, second %v", closeErr, secondCloseErr)
		}
		if source.closes != 1 {
			t.Fatalf("encoded response close count = %d, want 1", source.closes)
		}
		if (err == nil) != (wantErr == nil) {
			t.Fatalf("decode %s error = %v, reference error = %v", strings.Join(codings, ", "), err, wantErr)
		}
		if (closeErr == nil) != (wantCloseErr == nil) {
			t.Fatalf("close %s error = %v, reference close error = %v", strings.Join(codings, ", "), closeErr, wantCloseErr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("decoded %s body = %x, reference = %x", strings.Join(codings, ", "), got, want)
		}
		if mutation%4 == 0 && (!bytes.Equal(got, payload) || err != nil || closeErr != nil) {
			t.Fatalf("valid %s body = %x, %v; close = %v; want %x, nil, nil", strings.Join(codings, ", "), got, err, closeErr, payload)
		}
	})
}

func FuzzSupportedHTTPContentCodings(f *testing.F) {
	for _, seed := range []string{"", "gzip", "GZip, BR", "identity, zstd", "gzip,,br", "deflate", "gzip\x00br"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, joined string) {
		if len(joined) > 4<<10 {
			t.Skip()
		}
		values := strings.Split(joined, "\x00")
		got, supported := supportedHTTPContentCodings(values)
		want, wantSupported := referenceHTTPContentCodings(values)
		if supported != wantSupported || !slices.Equal(got, want) {
			t.Fatalf("content codings %q = %q, %t; want %q, %t", values, got, supported, want, wantSupported)
		}
	})
}

func decodeHTTPBodyReference(wire []byte, codings []string, width int) ([]byte, error, error) {
	reader := io.Reader(bytes.NewReader(wire))
	var closers []io.Closer
	closeDecoders := func() error {
		var err error
		for index := len(closers) - 1; index >= 0; index-- {
			if closeErr := closers[index].Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close reference decoder: %w", closeErr))
			}
		}
		return err
	}
	for index := len(codings) - 1; index >= 0; index-- {
		switch codings[index] {
		case "gzip":
			decoder, err := gzip.NewReader(reader)
			if err != nil {
				return nil, fmt.Errorf("initialize reference gzip decoder: %w", err), closeDecoders()
			}
			closers = append(closers, decoder)
			reader = decoder
		case "br":
			reader = brotli.NewReader(reader)
		case "zstd":
			decoder, err := zstd.NewReader(
				reader,
				zstd.WithDecoderConcurrency(1),
				zstd.WithDecoderLowmem(true),
				zstd.WithDecodeBuffersBelow(0),
				zstd.WithDecoderMaxWindow(httpZstdMaxWindow),
			)
			if err != nil {
				return nil, fmt.Errorf("initialize reference zstd decoder: %w", err), closeDecoders()
			}
			closers = append(closers, decoder.IOReadCloser())
			reader = decoder
		}
	}

	output, err := readFuzzBody(reader, width, 128<<10)
	return output, err, closeDecoders()
}

type countingReadCloser struct {
	io.Reader
	closes int
}

func (source *countingReadCloser) Close() error {
	source.closes++
	return nil
}

func readFuzzBody(reader io.Reader, width, maximum int) ([]byte, error) {
	output := make([]byte, 0, min(maximum, 4<<10))
	buffer := make([]byte, width)
	emptyReads := 0
	for len(output) <= maximum {
		count, err := reader.Read(buffer)
		output = append(output, buffer[:count]...)
		if err != nil {
			if err == io.EOF {
				return output, nil
			}
			return output, fmt.Errorf("read decoded fuzz body: %w", err)
		}
		if count == 0 {
			emptyReads++
			if emptyReads >= 100 {
				return output, io.ErrNoProgress
			}
			continue
		}
		emptyReads = 0
	}
	return output, fmt.Errorf("%w of %d bytes", errFuzzDecodedBodyTooLarge, maximum)
}

func referenceHTTPContentCodings(values []string) ([]string, bool) {
	var codings []string
	for _, value := range values {
		parts := strings.Split(value, ",")
		for _, part := range parts {
			coding := strings.ToLower(strings.TrimSpace(part))
			switch coding {
			case "gzip", "br", "zstd":
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
