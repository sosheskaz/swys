# Convert a key container

Convert a supported key to another standard container without changing whether it is private or public. The target must be compatible with the key type and identity.

Inputs accept one unencrypted PKCS#8, PKCS#1, or SEC1 private key or a PKIX public key in PEM or DER, or one unencrypted OpenSSH private key or authorized_keys public entry.

## Convert an OpenSSH public key to PKIX PEM

Use an existing id_ed25519.pub, or generate the example files first.

```sh
swys cert keygen --output private.pem --public-out id_ed25519.pub --public-format openssh
swys cert key-convert --input id_ed25519.pub --to pkix-pem --output public.pem
```

Convert private PEM to binary PKCS #8 DER.

```sh
swys cert key-convert --input private.pem --to pkcs8-der --output private.der
swys cert create --key private.der --dns localhost --output localhost.pem
```

The certificate command accepts the converted private key directly. Changing its container did not generate a new key.

Use cert key-public when the task is to derive public material from a private key. A container conversion alone does not remove private material.

## Reference

```sh
swys cert key-convert --help
swys help cert create
```
