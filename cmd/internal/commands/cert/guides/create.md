# Create a test certificate

Create a minimum-viable X.509 certificate for local tests and development. Supply an existing private key, or issue a certificate from a CSR using a local issuer. The default direct-key operation creates a self-signed leaf valid for 30 days.

With --output, NPC reads and validates the selected key and issuer artifacts and prepares the complete certificate before opening the destination. Artifact read, validation, or certificate creation failures leave that existing file unchanged. Shell redirection opens its destination before NPC runs.

## Create a localhost identity

Start in a fresh local directory and keep the private keys out of shared fixtures and source control.

```sh
umask 077
npc cert keygen > leaf-key.pem
npc cert create --key leaf-key.pem --dns localhost > leaf-cert.pem
npc cert inspect < leaf-cert.pem
```

## Sign the identity with a test CA

Use the leaf key above, then create a separate CA key and certificate. The leaf names localhost; the CA signs that identity without taking ownership of its private key.

```sh
npc cert keygen > ca-key.pem
npc cert create --ca --key ca-key.pem --subject 'CN=Local Test CA' > ca.pem
npc cert create --key leaf-key.pem --dns localhost --issuer-cert ca.pem --issuer-key ca-key.pem > signed-leaf.pem
npc cert inspect --format text < signed-leaf.pem
```

NPC **does not** install generated authorities into a trust store. Select the test CA explicitly in the client or an isolated test trust store.

Keep both private keys out of shared fixtures and source control. Share ca.pem with test clients that need to trust the issued certificate.

## Issue a certificate from a request

Use the leaf key and local issuer files created above. The CSR supplies the leaf's public key and identity; --csr issuance needs the issuer certificate and key, not the leaf's --key.

```sh
npc cert csr --key leaf-key.pem --dns localhost > leaf.csr
npc cert create --csr leaf.csr --issuer-cert ca.pem --issuer-key ca-key.pem > csr-leaf.pem
npc cert verify --ca ca.pem --hostname localhost < csr-leaf.pem
```

## Related guides

```sh
npc help cert keygen
npc help cert csr
npc help cert inspect
npc cert create --help
```
