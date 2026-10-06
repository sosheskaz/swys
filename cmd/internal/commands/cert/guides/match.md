# Match certificate public keys

Compare the public keys in any two or all three of a certificate, key, and certificate signing request. Matching does not check certificate trust, validity, names, or subjects.

## Match a certificate and private key

Create a local test identity, then compare its certificate with the key:

```sh
swys cert keygen --output server-key.pem
swys cert create --key server-key.pem --dns localhost --output server.pem
swys cert match --cert server.pem --key server-key.pem
```

For a signing request, SwYS also verifies the request signature. Create the request with the same key before comparing all three artifacts:

```sh
swys cert csr --key server-key.pem --dns localhost --output server.csr
swys cert match --cert server.pem --key server-key.pem --csr server.csr --format json
```

Use **--encoding base64** (or **-e base64**) to encode the complete text or JSON report, including its final newline. The default **raw** encoding leaves the report unchanged.

```sh
swys cert match --cert server.pem --key server-key.pem --format json --encoding base64 --output match.b64
```

Use **-** for at most one operand to read it from stdin. **--input** can redirect that stdin operand from a file.

```sh
swys cert match --cert server.pem --key - < server-key.pem
```

**--input-encoding** requires exactly one operand set to **-** and decodes only that operand. Named files use their own companion codecs, which default to raw. For a base64-wrapped copy of server-key.pem in server-key.pem.b64:

```sh
swys cert match --cert server.pem --key - --input server-key.pem.b64 --input-encoding base64
```

**--cert-encoding**, **--key-encoding**, and **--csr-encoding** decode each artifact independently. Supported codecs are raw, hex, base64 (also b64), base64url, and base32. These describe outer byte encoding; PEM's internal Base64 needs no codec.

Use the identity created above to prepare independently encoded inputs:

```sh
swys cert inspect --input server.pem --format pem --encoding base64 --output server.pem.b64
swys cert key-convert --input server-key.pem --to pkcs8-pem --encoding hex --output server-key.hex
swys cert match --cert server.pem.b64 --cert-encoding base64 --key server-key.hex --key-encoding hex --csr server.csr --format json
```

For an operand selected with **-**, choose either its companion codec or **--input-encoding**. Explicitly setting both is rejected, even with raw or identical codecs. A companion codec requires a nonempty source. Invalid selections fail before artifact reads or output mutation.

A completed mismatch produces a report with **match: false** and a nonzero exit status. Reports contain public fingerprints and never private key material.

## Reference

```sh
swys cert match --help
```
