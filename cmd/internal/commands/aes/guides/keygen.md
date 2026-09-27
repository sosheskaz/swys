# Generate an AES key

Generate a 256-bit raw key by default. Use --bits 128 for AES-128, or choose a cleartext Tink keyset with --key-format.

AES-192 is excluded because the Tink AES-GCM-HKDF streaming primitive used by NPC supports only 128-bit and 256-bit derived AES keys. NPC uses matching key sizes for key generation, streaming, raw GCM, and CBC so generated keys work across its AES modes. Go's standard AES implementation supports 192-bit keys; the common size restriction is an NPC compatibility choice.

```sh
npc aes keygen --output key.bin
printf 'example' | npc aes encrypt --keyfile key.bin --output message.gcm
npc aes decrypt --keyfile key.bin --input message.gcm
```

Raw output is binary key material. Tink JSON and binary outputs are standard cleartext AES-GCM-HKDF streaming keysets. Their key material is also unencrypted. Keep a generated key to decrypt later messages; a new key cannot recover them. Key files use sensitive-output protections.

For a Tink keyset, --chunk-size sets the ciphertext segment size; --hkdf-hash and --derived-key-bits select its key derivation parameters. These options do not apply to raw output.

```sh
npc aes keygen --key-format tink-json --output keyset.json
npc aes key-inspect --key-format tink-json --input keyset.json
```

## Reference

```sh
npc aes keygen --help
```
