# Generate, inspect, and convert keys

Use the key family for symmetric AES keys and supported asymmetric private or public keys. Private generation writes PKCS #8 PEM by default; inspection reports metadata without printing private material.

## Choose an operation

- **generate** creates new symmetric or asymmetric key material.
- **public** derives a public key from private material or canonicalizes a public key.
- **inspect** reports algorithm, size, and fingerprints.
- **convert** changes a key's standard container without changing private or public identity.

## Give a test service an identity

```sh
npc key generate ed25519 --output private.pem
npc key inspect --input private.pem
npc cert create --key private.pem --dns localhost --output localhost.pem
npc cert inspect --input localhost.pem
```

The certificate can be shared; the private key remains with the service. For encrypting data instead of identifying a service, generate an AES key and pass it to AES with the keyfile flag. The generate guide shows both workflows.

Treat generated private material as a secret. NPC protects regular private-key output files with owner-only permissions unless you explicitly select another mode.

## Next steps

```sh
npc help key generate
npc help key public
npc key --help
```
