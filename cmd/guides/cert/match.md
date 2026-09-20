# Match certificate public keys

Compare the public keys in any two or all three of a certificate, key, and certificate signing request. Matching does not check certificate trust, validity, names, or subjects.

## Match a certificate and private key

```sh
npc cert match --cert server.pem --key server-key.pem
```

For a signing request, NPC also verifies the request signature.

```sh
npc cert match --cert server.pem --key server-key.pem --csr server.csr --format json
```

Use **-** for at most one operand to read it from stdin. **--input** can redirect that stdin operand from a file.

```sh
npc cert match --cert server.pem --key - < server-key.pem
```

A completed mismatch produces a report with **match: false** and a nonzero exit status. Reports contain public fingerprints and never private key material.

## Reference

```sh
npc cert match --help
```
