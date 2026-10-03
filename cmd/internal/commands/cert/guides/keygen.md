# Generate a certificate private key

Generate an Ed25519 private key by default. Use --algorithm for P-256, P-384, or RSA.

Use --output to save the generated key and --mode to select file permissions. Key generation rejects --input because it has no payload to read.

```sh
npc cert keygen -o private.pem -P public.pem
npc cert create --key private.pem --dns localhost --output localhost.pem
```

The private key is PKCS#8 PEM and goes to --output/-o, or stdout when omitted. --public-out/-P optionally writes the matching public key to a separate file. --public-format selects pkix-pem (default), pkix-der, or openssh for that public key. Private output is sensitive; existing files must have acceptable permissions.

```sh
npc cert keygen --algorithm p256 --output p256.pem
npc cert keygen --algorithm rsa2048 --output rsa.pem
```

## Reference

```sh
npc cert keygen --help
```
