# Generate a raw AES key

Generate a 256-bit key by default. Use --bits 128 for AES-128.

AES-192 is excluded because the Tink AES-GCM-HKDF streaming primitive used by NPC supports only 128-bit and 256-bit derived AES keys. NPC uses matching key sizes for key generation, streaming, raw GCM, and CBC so generated keys work across its AES modes. Go's standard AES implementation supports 192-bit keys; the common size restriction is an NPC compatibility choice.

```sh
npc aes keygen --output key.bin
printf 'example' | npc aes encrypt --keyfile key.bin --output message.gcm
npc aes decrypt --keyfile key.bin --input message.gcm
```

The output is raw binary key material. Keep it to decrypt later messages; a new key cannot recover them. Key files use sensitive-output protections.

## Reference

```sh
npc aes keygen --help
```
