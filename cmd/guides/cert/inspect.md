# Inspect certificates from a file or stdin

Read PEM certificates and report identity, validity, fingerprints, and verification information. Multiple PEM certificates are kept in input order.

## Inspect a certificate

```sh
npc cert inspect --input server.pem
```

Use long output for additional fields, JSON for automation, or PEM when canonical certificate output is needed.

```sh
npc cert inspect --input chain.pem --format long
npc cert inspect --input chain.pem --format json
```

Inspection never prints private keys. A successful parse does not by itself establish trust; read the reported verification result and intended identity.

## Reference

```sh
npc cert inspect --help
```
