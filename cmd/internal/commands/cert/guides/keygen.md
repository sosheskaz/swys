# Generate a certificate private key

Generate an Ed25519 private key by default. Use --algorithm for P-256, P-384, or RSA.

Use --output to save the generated key and --mode to select file permissions. Key generation rejects --input because it has no payload to read.

```sh
swys cert keygen -o private.pem -P public.pem
swys cert create --key private.pem --dns localhost --output localhost.pem
```

The private key is PKCS#8 PEM and goes to --output/-o, or stdout when omitted. --public-out/-P optionally writes the matching public key to a separate file. --public-format selects pkix-pem (default), pkix-der, or openssh for that public key. Private output is sensitive; existing files must have acceptable permissions.

## Choose an algorithm or public container

- **ed25519** is the default signing key.
- **p256** and **p384** select ECDSA on the corresponding NIST curve.
- **rsa2048** and **rsa4096** select RSA with the named modulus size.

Choose the algorithm required by the certificate consumer. The default private container remains PKCS#8 PEM.

```sh
swys cert keygen --algorithm p256 --output p256.pem
swys cert keygen --algorithm rsa2048 --output rsa.pem
```

Use **cert key-public** to export the public key later, and **cert key-inspect** for metadata without printing private bytes.

```sh
swys cert key-inspect --input private.pem --format json
```

## Reference

```sh
swys help cert key-public
swys help cert key-inspect
swys cert keygen --help
```
