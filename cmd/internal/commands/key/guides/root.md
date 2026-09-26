# Inspect and convert keys

Use the key family to inspect, derive public material from, and convert asymmetric keys. Inspection reports metadata without printing private material. Generate private keys with cert keygen and raw AES keys with aes keygen.

## Choose an operation

- **public** derives a public key from private material or canonicalizes a public key.
- **inspect** reports algorithm, size, and fingerprints.
- **convert** changes a key's standard container without changing private or public identity.

## Give a test service an identity

```sh
npc cert keygen --output private.pem
npc key inspect --input private.pem
npc cert create --key private.pem --dns localhost --output localhost.pem
npc cert inspect --input localhost.pem
```

The certificate can be shared; the private key remains with the service. For encrypting data instead of identifying a service, generate an AES key and pass it to AES with the keyfile flag. The AES keygen guide shows the encryption workflow.

Treat generated private material as a secret. NPC protects regular private-key output files with owner-only permissions unless you explicitly select another mode.

## Next steps

```sh
npc help cert keygen
npc help aes keygen
npc help key public
npc key --help
```
