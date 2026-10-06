# Verify a certificate chain

Validate a leaf-first certificate chain for trust, time, purpose, and an optional DNS name or IP address. Extra certificates in the input and **--intermediates** are untrusted chain material; they do not become trust anchors.

## Verify with a private trust root

Create a disposable local authority and a certificate for api.example.test. The authority signs the leaf; no trust store is modified.

```sh
swys cert keygen --output root-key.pem
swys cert create --ca --key root-key.pem --subject 'CN=Local Test CA' --output root.pem
swys cert keygen --output server-key.pem
swys cert create --key server-key.pem --dns api.example.test --issuer-cert root.pem --issuer-key root-key.pem --output chain.pem
swys cert verify --input chain.pem --ca root.pem --hostname api.example.test
```

Keep both private keys local. The later examples assume chain.pem and root.pem are the corresponding certificate and trust anchor; use a hostname present in your certificate.

The main input is a contiguous leaf-first chain: each certificate after the leaf must be the valid issuer of the certificate before it. SwYS does not reorder this chain or accept unrelated certificates or gaps in it. Invalid order produces a **verified: false** report and a nonzero exit status. SwYS reports that all pieces are correct but ordered incorrectly only when cryptographic verification proves that diagnosis.

Use **--intermediates intermediates.pem** as an untrusted issuer pool to supply additional issuers, for example when the main input contains only the leaf. This pool can extend a contiguous partial chain, but it does not repair invalid order or gaps between certificates already included in the main input. **--ca** replaces the system roots unless **--system-ca** is also set.

To read trust anchors from standard input while the chain comes from a file:

```sh
cat root.pem | swys cert verify --input chain.pem --ca - --hostname api.example.test
```

Standard input has one owner. When **--ca -** or **--intermediates -** is used, the certificate chain must come from a file through **--input**; the default chain input and **--input -** are rejected.

**--input-encoding** decodes only the main certificate chain. **--ca-encoding** and **--intermediates-encoding** independently decode their selected sources, including stdin. Both default to raw and support raw, hex, base64 (also b64), base64url, and base32. These describe outer byte encoding; PEM's internal Base64 needs no outer codec. A companion codec requires a nonempty corresponding source; invalid selections fail before reading artifacts or opening output.

For a base64-wrapped chain file in chain.pem.b64:

```sh
cat root.pem | swys cert verify --input chain.pem.b64 --input-encoding base64 --ca - --hostname api.example.test
```

To independently decode the main chain and CA stdin, prepare encoded copies of the artifacts created above:

```sh
swys cert inspect --input chain.pem --format pem --encoding base64 --output chain.pem.b64
swys cert inspect --input root.pem --format pem --encoding hex --output root.pem.hex
swys cert verify --input chain.pem.b64 --input-encoding base64 --ca - --ca-encoding hex --hostname api.example.test < root.pem.hex
```

**--intermediates -** reads untrusted intermediate certificates from stdin. The main chain must come from a file, and **--ca** must use a file or system roots. For the same local identity, the issuer can also be supplied to the untrusted pool while root.pem remains the explicit trust anchor:

```sh
swys cert verify --input chain.pem --ca root.pem --intermediates - --hostname api.example.test < root.pem
```

An exact **-** selects stdin; **./-** names a literal file.

Check that the issued certificate also belongs to the intended key:

```sh
swys cert match --cert chain.pem --key server-key.pem --format json
```

Use **--purpose client** for a client certificate or **--purpose any** to accept any extended key usage. Use **--at** with an RFC 3339 timestamp for reproducible checks.

With a client certificate in client.pem and its untrusted issuer in issuer.pem:

```sh
swys cert verify --input client.pem --intermediates issuer.pem --ca root.pem --purpose client --at 2026-01-01T00:00:00Z --format json
```

Use **--encoding base64** (or **-e base64**) to encode the entire report, including its final newline, for transport. The default **raw** encoding leaves the selected text or JSON format unchanged.

```sh
swys cert verify --input chain.pem --ca root.pem --hostname api.example.test --format json --encoding base64 --output report.b64
```

A readable certificate that fails verification produces a report with **verified: false** and a nonzero exit status. SwYS does not fetch missing certificates, OCSP responses, or CRLs.

## Reference

```sh
swys cert verify --help
```
