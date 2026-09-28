# Inspect AES key metadata

Show the size of a raw AES key or the primary ID, status, size, and streaming parameters of a cleartext Tink keyset. Inspection never prints key material.

```sh
npc aes key-inspect --input key.bin
npc aes key-inspect --input keyset.json --format json
```

The input format is detected by default. Use --key-format raw, tink-json, or tink-binary to select one explicitly. Use --format text or --format json for the report.

## Reference

```sh
npc aes key-inspect --help
```
