# Create a certificate signing request

Create a PKCS #10 request from an existing private key. The request contains the chosen subject and requested DNS or IP subject alternative names. This command does not contact a certificate authority or issue a certificate; use npc cert create --csr to issue one locally.

With --output, NPC reads and validates the key and prepares the complete request before opening the destination. Key read, validation, or request creation failures leave that existing file unchanged. Shell redirection opens its destination before NPC runs.

## Request a server identity

Start in a fresh local directory and keep the private key local.

```sh
umask 077
npc cert keygen > server-key.pem
npc cert csr --key server-key.pem --dns service.example.test > server.csr
```

Send the request to the intended certificate authority using that authority's approved process. Keep the private key local; only the request needs to leave the machine.

## Issue locally with a test CA

Use server.csr from above, then create a separate local issuer key and CA certificate. Issuance uses the request's public key and identity; do not supply the server's --key with --csr.

```sh
npc cert keygen > ca-key.pem
npc cert create --ca --key ca-key.pem --subject 'CN=Local Test CA' > ca.pem
npc cert create --csr server.csr --issuer-cert ca.pem --issuer-key ca-key.pem > server-cert.pem
npc cert verify --ca ca.pem --hostname service.example.test < server-cert.pem
```

This does not install the CA in a trust store. Keep both private keys local and select ca.pem explicitly when trusting this test identity.

## Related guides

```sh
npc help cert create
npc help cert inspect
npc cert csr --help
```
