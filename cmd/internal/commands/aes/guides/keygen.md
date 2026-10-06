# Generate an AES key

Generate a 256-bit raw key by default. Use --bits 128 for AES-128, or choose a cleartext Tink keyset with --key-format.

Use --output to save the generated key and --mode to select file permissions. Key generation rejects --input because it has no payload to read.

AES-192 is excluded because the Tink AES-GCM-HKDF streaming primitive used by SwYS supports only 128-bit and 256-bit derived AES keys. SwYS supports raw 128-bit and 256-bit keys for its OpenPGP and Tink streaming formats.

```sh
swys aes keygen --output key.bin
printf 'example' | swys aes encrypt --key key.bin --output message.pgp
swys aes decrypt --key key.bin --input message.pgp
```

Raw output is binary key material. Tink JSON and binary outputs are standard cleartext AES-GCM-HKDF streaming keysets. Their key material is also unencrypted. Keep a generated key to decrypt later messages; a new key cannot recover them. Key files use sensitive-output protections.

For a Tink keyset, --chunk-size sets the ciphertext segment size; --hkdf-hash and --derived-key-bits select its key derivation parameters. These options do not apply to raw output.

```sh
swys aes keygen --key-format tink-json --output keyset.json
swys aes key-inspect --key-format tink-json --input keyset.json
```

## Reference

```sh
swys aes keygen --help
```
