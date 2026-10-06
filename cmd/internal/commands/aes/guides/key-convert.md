# Convert AES key containers

Convert a raw AES key or a cleartext Tink AES-GCM-HKDF streaming keyset between raw, Tink JSON, and Tink binary formats. Tink JSON and binary conversions preserve every key, ID, status, primary selection, and parameter.

## Convert a keyset

```sh
swys aes keygen --key-format tink-json --output keyset.json
swys aes key-convert --to tink-binary --input keyset.json --output keyset.bin
swys aes key-inspect --input keyset.bin
```

The source format is detected by default. Use --from raw, tink-json, or tink-binary to select one explicitly. --to is required. Converting a keyset to raw exports the sole key. For a keyset with multiple entries, choose an enabled key with --key-id. Raw output loses keyset metadata, while preserving the selected key bytes. A raw key imported into a Tink keyset receives a new random key ID; its derived key size defaults to the raw key size.

Keysets are cleartext and contain secret material. The output uses sensitive-file protections.

## Reference

```sh
swys aes key-convert --help
```
