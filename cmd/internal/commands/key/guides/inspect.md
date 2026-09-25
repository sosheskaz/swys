# Inspect key metadata

Read one supported private or public key and report its algorithm, size, and public fingerprints. Private key bytes are never included in the report.

## Inspect a key file

```sh
npc key inspect --input private.pem
npc key inspect --input public.pem --format json
```

Inspection accepts the supported PEM, DER, and OpenSSH public containers. It does not decrypt password-protected private keys.

Use the public operation to emit a shareable public key rather than copying information from the inspection report.

```sh
npc help key public
npc key inspect --help
```
