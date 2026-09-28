# Encrypt a message with AES

Encryption defaults to binary, uncompressed OpenPGP RFC 9580 AES-GCM. Supply a raw AES key as base64 with --key or use --keyfile for a raw key or cleartext Tink JSON or binary keyset. Keyfile format is detected from its contents by default; --key-format raw, tink-json, or tink-binary selects a format explicitly.

## Encrypt with a raw key file

```sh
npc aes keygen --output key.bin
printf 'deploy at 09:00' | npc aes encrypt --keyfile key.bin --output message.pgp
```

OpenPGP accepts power-of-two --chunk-size values from 64 bytes through 4 MiB, defaulting to 1 MiB. A Tink keyset uses its enabled primary key by default. Use --key-id to select another enabled key. OpenPGP does not use external --aad or Tink HKDF flags.

## Encrypt with a password

Choose exactly one of --password (hidden prompt on the controlling terminal), --password-env NAME, or --password-command SHELL_COMMAND. Encryption confirms a prompted password. The password command's first stdout line supplies the password, while its remaining stdout is ignored; its stdin is disconnected from the plaintext stream.

```sh
printf 'deploy at 09:00' | npc aes encrypt --password --output message.pgp
```

A password produces a standard OpenPGP message: an AES-256 SKESK v6 wrapper using Argon2id, then the SEIPDv2 AES-GCM stream. The default cost is --kdf-memory 64MiB, --kdf-passes 3, and --kdf-parallelism 4. Memory must be a power of two of at least 8 KiB per lane. Costs above 256MiB, 10 passes, or 16 lanes are rejected before the password is requested. Passwords cannot be combined with Tink, keysets, or --aad.

On macOS, Linux, and FreeBSD, Ctrl-Z while an interactive password command reads the terminal cancels password acquisition. NPC ends the supplier process group, restores the terminal, and reports that the command was suspended.

## Encrypt in Tink format

Tink uses the exact --aad bytes supplied by the user. Raw keys default to 1 MiB ciphertext segments, SHA-256 HKDF, and a derived AES key matching the raw key size. A Tink keyset supplies its own parameters and primary encryption key.

```sh
printf 'payload' | npc aes encrypt --wire-format tink --keyfile key.bin --aad production --output payload.tink
```

## Reference

```sh
npc aes encrypt --help
```
