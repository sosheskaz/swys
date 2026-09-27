# Inspect AES key metadata

Show the size of a raw AES key or the primary ID, status, size, and streaming parameters of a cleartext Tink keyset. Inspection never prints key material.

```sh
npc aes key-inspect --input key.bin
npc aes key-inspect --key-format tink-json --input keyset.json --format json
```

Raw input is the default. Choose tink-json or tink-binary for keysets. Use --format text or --format json for the report.

## Reference

```sh
npc aes key-inspect --help
```
