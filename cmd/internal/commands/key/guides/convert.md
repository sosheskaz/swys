# Convert a key container

Convert a supported key to another standard container without changing whether it is private or public. The target must be compatible with the key type and identity.

## Convert an OpenSSH public key to PKIX PEM

Use an existing id_ed25519.pub, or generate the example files first.

```sh
npc cert keygen --output private.pem --public-out id_ed25519.pub --public-format openssh
npc key convert --input id_ed25519.pub --to pkix-pem --output public.pem
```

Convert private PEM to binary PKCS #8 DER.

```sh
npc key convert --input private.pem --to pkcs8-der --output private.der
npc cert create --key private.der --dns localhost --output localhost.pem
```

The certificate command accepts the converted private key directly. Changing its container did not generate a new key.

Use key public when the task is to derive public material from a private key. A container conversion alone does not remove private material.

## Reference

```sh
npc key convert --help
npc help cert create
```
