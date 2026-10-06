# Inspect AES key metadata

Show the size of a raw AES key or the primary ID, status, size, and streaming parameters of a cleartext Tink keyset. Inspection never prints key material.

## Inspect a local key

Create a raw key or Tink keyset first; inspection reads that key file.

```sh
swys aes keygen --output key.bin
swys aes key-inspect --input key.bin
swys aes keygen --key-format tink-json --output keyset.json
swys aes key-inspect --input keyset.json --format json
```

## Use the metadata

With jq installed, extract the primary key ID for a keyset inventory:

```sh
swys aes key-inspect --input keyset.json --format json | jq '.primary_key_id'
```

Use **--encoding base64** (or **-e base64**) to encode the entire metadata report, including any final newline. The default **raw** encoding leaves the selected format unchanged.

```sh
swys aes key-inspect --input keyset.json --format json --encoding base64 --output key-report.b64
```

The input format is detected by default. Use --key-format raw, tink-json, or tink-binary to select one explicitly. Use --format text or --format json for the report.

## Reference

```sh
swys aes key-inspect --help
```
