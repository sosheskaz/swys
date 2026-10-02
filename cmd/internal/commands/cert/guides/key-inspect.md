# Inspect key metadata

Read one supported private or public key and report its algorithm, size, and public fingerprints. Private key bytes are never included in the report.

Inputs accept one unencrypted PKCS#8, PKCS#1, or SEC1 private key or a PKIX public key in PEM or DER, or one unencrypted OpenSSH private key or authorized_keys public entry.

## Inspect a key file

```sh
npc cert key-inspect --input private.pem
npc cert key-inspect --input public.pem --format json
```

Use **--encoding base64** (or **-e base64**) to encode the entire metadata report, including its final newline. The default **raw** encoding leaves the selected format unchanged.

```sh
npc cert key-inspect --input public.pem --format json --encoding base64 --output key-report.b64
```

Inspection accepts the supported PEM, DER, and OpenSSH public containers. It does not decrypt password-protected private keys.

Use the public operation to emit a shareable public key rather than copying information from the inspection report.

```sh
npc help cert key-public
npc cert key-inspect --help
```
