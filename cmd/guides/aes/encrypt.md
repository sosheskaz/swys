# Encrypt a message with AES

Encrypt plaintext with AES-GCM-HKDF streaming by default. Supply a base64 key directly or read raw key bytes from a file. Binary ciphertext goes to stdout unless an output file or encoding is selected.

## Encrypt with a key file

Create the key once, then protect a message.

```sh
npc key generate aes256 --output key.bin
printf 'deploy at 09:00' | npc aes encrypt --keyfile key.bin --output message.gcm
```

The default --chunk-size is 1M, meaning at most 1,048,576 plaintext bytes per segment. Sizes from 64 bytes through 64 MiB are accepted. K, M, and G use binary multiples; KB, MB, and GB use decimal multiples. KiB, MiB, and GiB also use binary multiples. A decimal fraction is accepted when the result is a whole byte, such as 1.5KB. Encryption buffers a segment with lookahead and does not promise interactive flush timing.

Additional authenticated data is checked during decryption but is not stored in the ciphertext. The decrypting side must supply the same value.

```sh
printf 'payload' | npc aes encrypt --keyfile key.bin --aad production --output payload.gcm
```

For the legacy single-message GCM format, select --raw explicitly. It retains a 64 MiB plaintext limit. Use CBC only for an existing compatibility requirement. CBC does not authenticate ciphertext. AES-192 keys are no longer supported.

## Reference

```sh
npc aes encrypt --help
```
