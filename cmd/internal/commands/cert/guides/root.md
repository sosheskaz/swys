# Work with X.509 certificates

Use the certificate family to inspect existing certificates, retrieve a server chain, create short-lived test identities, and work with asymmetric keys. SwYS reports certificate details but does not install trust anchors or manage a production certificate authority.

## Choose an operation

Run swys cert for the operation reference.

- **inspect** reads one or more PEM certificates from stdin or a file.
- **connect** retrieves certificates presented by a TLS endpoint.
- **create** makes a self-signed test certificate, a test CA, or a leaf signed by that CA.
- **csr** creates a PKCS #10 signing request for an existing private key.
- **verify** validates a leaf-first certificate chain against explicit or system trust roots.
- **key-public** derives or canonicalizes a public key.
- **key-convert** changes a key container without changing private or public identity.
- **key-inspect** reports key metadata without private material.
- **match** compares the public keys in certificates, keys, and signing requests.

For the certificate and path-validation model, see [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280).

## Create and inspect a localhost identity

Generate a private key, issue a self-signed test certificate for it, then inspect the certificate's names and validity.

```sh
swys cert keygen --output server-key.pem
swys cert create --key server-key.pem --dns localhost --output server-cert.pem
swys cert inspect --input server-cert.pem --format text
```

The key stays private; the certificate can be shared with peers. Self-signing does not make it trusted by other clients. The create guide shows a small test CA when several identities need the same trust anchor.

## Next steps

```sh
swys help cert connect
swys help cert create
swys help cert verify
swys help cert match
swys cert --help
```
