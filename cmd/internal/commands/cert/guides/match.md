# Match certificate public keys

Compare the public keys in any two or all three of a certificate, key, and certificate signing request. Matching does not check certificate trust, validity, names, or subjects.

## Match a certificate and private key

Create a local test identity, then compare its certificate with the key:

```sh
npc cert keygen --output server-key.pem
npc cert create --key server-key.pem --dns localhost --output server.pem
npc cert match --cert server.pem --key server-key.pem
```

For a signing request, NPC also verifies the request signature. Create the request with the same key before comparing all three artifacts:

```sh
npc cert csr --key server-key.pem --dns localhost --output server.csr
npc cert match --cert server.pem --key server-key.pem --csr server.csr --format json
```

Use **--encoding base64** (or **-e base64**) to encode the complete text or JSON report, including its final newline. The default **raw** encoding leaves the report unchanged.

```sh
npc cert match --cert server.pem --key server-key.pem --format json --encoding base64 --output match.b64
```

Use **-** for at most one operand to read it from stdin. **--input** can redirect that stdin operand from a file.

```sh
npc cert match --cert server.pem --key - < server-key.pem
```

**--input-encoding** requires exactly one operand set to **-** and decodes only that operand. Named files remain raw. For a base64-wrapped copy of server-key.pem in server-key.pem.b64:

```sh
npc cert match --cert server.pem --key - --input server-key.pem.b64 --input-encoding base64
```

A completed mismatch produces a report with **match: false** and a nonzero exit status. Reports contain public fingerprints and never private key material.

## Reference

```sh
npc cert match --help
```
