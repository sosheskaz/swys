# Inspect AES key metadata

Show the size of a raw AES key or the primary ID, status, size, and streaming parameters of a cleartext Tink keyset. Inspection never prints key material.

```sh
npc aes key-inspect --input key.bin
npc aes key-inspect --input keyset.json --format json
```

Use **--encoding base64** (or **-e base64**) to encode the entire metadata report, including any final newline. The default **raw** encoding leaves the selected format unchanged.

```sh
npc aes key-inspect --input keyset.json --format json --encoding base64 --output key-report.b64
```

The input format is detected by default. Use --key-format raw, tink-json, or tink-binary to select one explicitly. Use --format text or --format json for the report.

## Reference

```sh
npc aes key-inspect --help
```
