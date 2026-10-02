# Create a test certificate

Create a minimum-viable X.509 certificate for local tests and development. Supply an existing private key. The default is a self-signed leaf valid for 30 days.

## Create a localhost identity

```sh
npc cert keygen --output leaf-key.pem
npc cert create --key leaf-key.pem --dns localhost --output leaf-cert.pem
npc cert inspect --input leaf-cert.pem
```

## Sign the identity with a test CA

Use the leaf key above, then create a separate CA key and certificate. The leaf names localhost; the CA signs that identity without taking ownership of its private key.

```sh
npc cert keygen --output ca-key.pem
npc cert create --ca --key ca-key.pem --subject 'CN=Local Test CA' --output ca.pem
npc cert create --key leaf-key.pem --dns localhost --issuer-cert ca.pem --issuer-key ca-key.pem --output signed-leaf.pem
npc cert inspect --input signed-leaf.pem --format text
```

NPC **does not** install generated authorities into a trust store. Select the test CA explicitly in the client or an isolated test trust store.

Keep both private keys out of shared fixtures and source control. Share ca.pem with test clients that need to trust the issued certificate.

## Related guides

```sh
npc help cert keygen
npc help cert inspect
npc cert create --help
```
