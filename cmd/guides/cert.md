# Work with X.509 certificates

Use the certificate family to inspect existing certificates, retrieve a server chain, or create short-lived test identities. NPC reports certificate details but does not install trust anchors or manage a production certificate authority.

## Choose an operation

- **inspect** reads one or more PEM certificates from stdin or a file.
- **connect** retrieves certificates presented by a TLS endpoint.
- **create** makes a self-signed test certificate, a test CA, or a leaf signed by that CA.
- **csr** creates a PKCS #10 signing request for an existing private key.

For the certificate and path-validation model, see [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280).

## Create and inspect a localhost identity

Generate a private key, issue a self-signed test certificate for it, then inspect the certificate's names and validity.

```sh
npc key generate ed25519 --output server-key.pem
npc cert create --key server-key.pem --dns localhost --output server-cert.pem
npc cert inspect --input server-cert.pem --format long
```

The key stays private; the certificate can be shared with peers. Self-signing does not make it trusted by other clients. The create guide shows a small test CA when several identities need the same trust anchor.

## Next steps

```sh
npc help cert connect
npc help cert create
npc cert --help
```
