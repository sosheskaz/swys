# Command output contract

Use this contract when adding or changing a public command's output interface. Apply the stages in order:

1. **Operation** obtains a result and determines its outcome, including any required verification. Later stages must not revise that outcome, although their own failures still fail the command.
2. **Selection** chooses which domain objects to export. A selection does not change the operation's outcome or discard verification information needed in a report. Return selection failures with their error identity intact.
3. **Format** serializes the selected objects as text, JSON, PEM, or another command-supported representation. Human text may offer detail variants; a formatter must not fetch data, choose domain objects, or change the operation's verification outcome. Return serialization failures with their error identity intact.
4. **Output encoding** (`--encoding`/`-e`) transforms the complete serialized stdout byte stream, including delimiters and newlines. For example, base64 of PEM includes its header, footer, and line breaks. A binary field encoded inside a JSON document is part of that JSON schema and is independent of this whole-output encoding.
5. **Destination** sends those bytes to Cobra's configured stdout or the selected output file. Diagnostics go to stderr outside the output encoder; structured verification data remains in reports when the format supports it.

The stages describe responsibility and observable behavior, not a requirement to buffer a whole response. Preserve streaming, cancellation, and error identity when wrapping failures. Validate flags, incompatible choices, and codecs before opening or truncating an output file. Preserve existing same-file and sensitive-output protections. Report write, encoder-finalization, and destination-close failures; where output has already streamed, an error can leave partial bytes. Close an output filter before its file so buffered bytes and finalization errors are handled in order.

Wire formats and key-container formats describe cryptographic or input data, not presentation. Keep `--wire-format` and `--key-format` separate from output `--format` and `--encoding`. Input decoding is likewise separate from output encoding.

The hash commands have one explicit exception: they encode the digest, finalize the encoder, then append one **unencoded** newline for non-raw encodings; raw digests have no newline. Do not generalize that framing rule to other commands.

This is normative for new and updated output interfaces. Existing commands may still differ until migrated.

## Review checklist

- Identify the operation, selection, format, encoding, and destination consumers before editing; record any boundary that cannot be verified.
- Check that selection and formatting preserve the operation and verification outcomes, propagate their own failures, and preserve each supported format's existing documented schema unless intentionally changed. Keep diagnostics on stderr.
- Check validation before output-file mutation and cover streaming, cancellation, partial writes, encoder finalization, and close errors where applicable.
- Exercise the changed behavior through the root command with its I/O hooks and update the owning embedded guide.

## Human presentation

Human reports default to `--format text`. Commands that support text also support
`--format plain` with the same layout and no generated ANSI controls. The shared
`--style auto|rich|plain` flag controls styling; plain format takes precedence.
Style applies independently to the original stdout and stderr destinations.
Auto requires a terminal, no nonempty `NO_COLOR`, and no `TERM=dumb`; output files
and encoded stdout default to plain even when the original stream was a terminal.
An explicit rich style overrides automatic detection, but never plain format.

Capture terminal size and presentation before commandio replaces or encodes
streams. Tables use the full reported width and fall back to labeled records when
they cannot fit. Unknown or redirected widths use 100 columns for layout
selection. Keep values on logical lines and defer wrapping to the terminal; never
truncate or split names, TXT tokens, fingerprints, or other copyable values.
The shared renderer measures Unicode display cells before styling and escapes
untrusted controls in report values. Styling adds SGR only and resets before
payloads. Rich help retains its separate 80-column layout; plain help never adds
wrapping. Help retains its hyperlink/pager policy.

Presentation does not decorate JSON, PEM, key material, ciphertext, raw network
streams, HTTP bodies, or digests. HTTP response headers retain wire-like framing;
gRPC text retains protobuf syntax and list framing. Output encoding still covers
the entire formatted stdout, including delimiters and newlines. Diagnostics remain
outside that encoder.
