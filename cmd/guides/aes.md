# Encrypt and decrypt with AES

Use the AES family when you already have a 128-bit or 256-bit symmetric key. AES-GCM-HKDF streaming is the authenticated default. AES-CBC remains available for compatibility with systems that require it.

## Choose an operation

- **encrypt** protects plaintext with a supplied key.
- **decrypt** opens ciphertext made with the same mode, key, and additional data.

## Start with an authenticated stream

```sh
npc key generate aes256 --output key.bin
printf 'secret message' | npc aes encrypt --keyfile key.bin --output message.gcm
npc aes decrypt --keyfile key.bin --input message.gcm
```

Keep the key separate from ciphertext. Encryption uses a fresh Tink stream header. The default maximum plaintext chunk is 1 MiB; use --chunk-size on encryption to change it. Decryption reads that size from the stream. Streams have a finite segment-count limit and buffer segments with lookahead, so they do not provide interactive flush timing.

Existing single-message GCM ciphertext requires --raw on decryption. Use --raw on encryption to create that legacy format. Raw mode retains a 64 MiB message limit. AES-192 keys are no longer supported.

## Next steps

```sh
npc help aes encrypt
npc help aes decrypt
npc help key generate
npc aes --help
```
