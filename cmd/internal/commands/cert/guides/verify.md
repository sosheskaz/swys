# Verify a certificate chain

Validate a leaf-first certificate chain for trust, time, purpose, and an optional DNS name or IP address. Extra certificates in the input and **--intermediates** are untrusted chain material; they do not become trust anchors.

## Verify with a private trust root

Create a disposable local authority and a certificate for api.example.test. The authority signs the leaf; no trust store is modified.

```sh
npc cert keygen --output root-key.pem
npc cert create --ca --key root-key.pem --subject 'CN=Local Test CA' --output root.pem
npc cert keygen --output server-key.pem
npc cert create --key server-key.pem --dns api.example.test --issuer-cert root.pem --issuer-key root-key.pem --output chain.pem
npc cert verify --input chain.pem --ca root.pem --hostname api.example.test
```

Keep both private keys local. The later examples assume chain.pem and root.pem are the corresponding certificate and trust anchor; use a hostname present in your certificate.

The main input is a contiguous leaf-first chain: each certificate after the leaf must be the valid issuer of the certificate before it. NPC does not reorder this chain or accept unrelated certificates or gaps in it. Invalid order produces a **verified: false** report and a nonzero exit status. NPC reports that all pieces are correct but ordered incorrectly only when cryptographic verification proves that diagnosis.

Use **--intermediates intermediates.pem** as an untrusted issuer pool to supply additional issuers, for example when the main input contains only the leaf. This pool can extend a contiguous partial chain, but it does not repair invalid order or gaps between certificates already included in the main input. **--ca** replaces the system roots unless **--system-ca** is also set.

To read trust anchors from standard input while the chain comes from a file:

```sh
cat root.pem | npc cert verify --input chain.pem --ca - --hostname api.example.test
```

Standard input has one owner. When **--ca -** is used, the certificate chain must come from a file through **--input**; the default chain input and **--input -** are rejected.

**--input-encoding** decodes only the main certificate chain. Named CA and intermediate files, and CA standard input selected by **--ca -**, remain raw certificate bytes.

For a base64-wrapped chain file in chain.pem.b64:

```sh
cat root.pem | npc cert verify --input chain.pem.b64 --input-encoding base64 --ca - --hostname api.example.test
```

Check that the issued certificate also belongs to the intended key:

```sh
npc cert match --cert chain.pem --key server-key.pem --format json
```

Use **--purpose client** for a client certificate or **--purpose any** to accept any extended key usage. Use **--at** with an RFC 3339 timestamp for reproducible checks.

With a client certificate in client.pem and its untrusted issuer in issuer.pem:

```sh
npc cert verify --input client.pem --intermediates issuer.pem --ca root.pem --purpose client --at 2026-01-01T00:00:00Z --format json
```

Use **--encoding base64** (or **-e base64**) to encode the entire report, including its final newline, for transport. The default **raw** encoding leaves the selected text or JSON format unchanged.

```sh
npc cert verify --input chain.pem --ca root.pem --hostname api.example.test --format json --encoding base64 --output report.b64
```

A readable certificate that fails verification produces a report with **verified: false** and a nonzero exit status. NPC does not fetch missing certificates, OCSP responses, or CRLs.

## Reference

```sh
npc cert verify --help
```
