> Historical format: current SwYS AES commands no longer read or write this format. Use an older NPC binary for recovery.

# NPC AES stream format, version 1

The default `npc aes encrypt` output is a 16-byte NPC envelope header followed
immediately by an unmodified Tink AES-GCM-HKDF stream. `npc aes decrypt` requires
this format unless `--raw` selects the legacy single-message GCM wire format.

| Offset | Bytes | Value                                             |
| ------ | ----: | ------------------------------------------------- |
| 0      |     8 | ASCII `NPCENC` followed by CR LF                  |
| 8      |     1 | Version `1`                                       |
| 9      |     1 | Suite `1` for AES-128 or `2` for AES-256          |
| 10     |     2 | Header length `16`, unsigned big-endian           |
| 12     |     4 | Maximum plaintext chunk size, unsigned big-endian |

The chunk size is between 64 and 67,108,864 bytes. The Tink primitive is
`AESGCMHKDF` with HKDF-SHA256, a derived AES key the same size as the supplied
key, a ciphertext segment size of chunk size plus 16, and first segment offset
zero. Tink's own header is 24 bytes for AES-128 or 40 bytes for AES-256, leaving
that many fewer plaintext bytes in the first segment. Following plaintext
segments can hold the full chunk size.

The Tink associated data is the byte concatenation of
`npc/aes-gcm-stream/v1\0` (where `\0` is one NUL byte), the exact 16-byte
NPC header, and the caller's
`--aad` bytes. The header is visible, then bound by authentication. The stream
does not store the caller's AAD. Tink handles salt, nonce prefix, segment
numbers, the final marker, and its finite segment-count limit. A recipient
must reject an unknown version, suite, header length, or invalid chunk size
before allocating segment buffers; it must also reject trailing data and
truncated or concatenated streams. Output from earlier authenticated segments
may remain after a later segment fails authentication.

This format pins [Tink Go v2.8.0](https://pkg.go.dev/github.com/tink-crypto/tink-go/v2@v2.8.0/streamingaead/subtle).
Its implementation uses the literal `SHA256` for the HKDF algorithm parameter.
The implementation rejects segment counter values at or above 2^32 - 1.
