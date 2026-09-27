# Encrypt a message with AES

Encryption defaults to binary, uncompressed OpenPGP RFC 9580 AES-GCM. Supply a raw AES key as base64 with --key or from a file with --keyfile. Use --key-format tink-json or tink-binary for a cleartext Tink keyset.

## Encrypt with a raw key file

```sh
npc aes keygen --output key.bin
printf 'deploy at 09:00' | npc aes encrypt --keyfile key.bin --output message.pgp
```

OpenPGP accepts power-of-two --chunk-size values from 64 bytes through 4 MiB, defaulting to 1 MiB. When using a Tink keyset with OpenPGP, provide --key-id to select an enabled key. OpenPGP does not use external --aad or Tink HKDF flags.

## Encrypt in Tink format

Tink uses the exact --aad bytes supplied by the user. Raw keys default to 1 MiB ciphertext segments, SHA-256 HKDF, and a derived AES key matching the raw key size. A Tink keyset supplies its own parameters and primary encryption key.

```sh
printf 'payload' | npc aes encrypt --wire-format tink --keyfile key.bin --aad production --output payload.tink
```

## Reference

```sh
npc aes encrypt --help
```
