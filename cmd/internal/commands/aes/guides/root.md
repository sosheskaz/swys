# Encrypt and decrypt with AES

Use a raw 128-bit or 256-bit AES key, a cleartext Tink streaming keyset, or a password. AES commands that read keys detect their format from contents by default. Encryption defaults to binary OpenPGP RFC 9580 AES-GCM. Select --wire-format tink for native Tink AES-GCM-HKDF streams.

## Choose an operation

- **keygen** creates a raw AES key or cleartext Tink keyset.
- **key-convert** converts raw keys and Tink JSON or binary keysets.
- **key-inspect** shows key metadata without revealing key material.
- **encrypt** protects plaintext in the selected standard wire format.
- **decrypt** opens ciphertext in the explicitly selected wire format.

## Start with a raw key

```sh
swys aes keygen --output key.bin
printf 'secret message' | swys aes encrypt --key key.bin --output message.pgp
swys aes decrypt --key key.bin --input message.pgp
```

OpenPGP records a power-of-two chunk size from 64 bytes through 4 MiB; the default is 1 MiB. Tink uses ciphertext segments from 64 bytes through 64 MiB. Tink keyset parameters are authoritative. An explicit conflicting override is rejected.

A password selects OpenPGP AES-256 with an Argon2id password wrapper; see the encrypt and decrypt guides for its cost limits.

Historical SwYS v1/v2 streams, raw GCM messages, and CBC ciphertext require an older SwYS binary. There is no format detection or authentication-failure fallback.

## Reference

```sh
swys aes --help
```
