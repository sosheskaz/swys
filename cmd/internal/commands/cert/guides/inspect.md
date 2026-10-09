# Inspect certificates from a file or stdin

Read a PEM certificate bundle or one DER certificate and report identity, validity, fingerprints, and verification information. By default, all supplied certificates are displayed as text, in input order; verification describes the first certificate.

## Inspect or export certificates

The examples below require a certificate or leaf-first bundle in chain.pem. Use **swys help cert create** to create a local test identity, or export a reachable endpoint's certificates with **cert connect**.

```sh
swys cert inspect --input chain.pem --format text
swys cert inspect --input chain.pem --format json
swys cert inspect --input chain.pem --select leaf -f pem -o server.pem
swys cert inspect --input chain.pem --select root -f pem -e base64
```

PEM and DER are recognized automatically. Use **--input-encoding** to decode wrapped certificate bytes before parsing; the default **raw** reads them unchanged.

```sh
swys cert inspect --input certificate.der --format json
swys cert inspect --input chain.pem.b64 --input-encoding base64 --format json
```

For a reachable TLS endpoint, decode an encoded certificate export directly:

```sh
swys cert connect api.example.com:443 --select leaf -f pem -e base64 | swys cert inspect --input-encoding base64
```

The default **text** format displays detailed certificate metadata, validity dates, fingerprints, and certificate verification.

**--select leaf|chain|fullchain|root** (or **-s**) chooses the certificate material independently of **--format text|json|pem**. **chain** excludes the first certificate; **fullchain** preserves all supplied certificates without adding roots. **root** exports CA trust anchors from verified chains, or a supplied self-signed CA connected by a leaf-first signature chain when trust verification fails. Multiple verified roots are deduplicated and sorted by SHA-256 fingerprint. Unavailable selections return an error and preserve existing output files.

A non-negative integer selects one certificate from a complete, unambiguous chain in root-to-leaf order: **0** is the root, **1** is the next certificate toward the leaf, and **n-1** is the leaf for a chain of **n** certificates. SwYS uses a verified chain when available, otherwise a complete supplied signature chain. Missing roots, multiple distinct verified paths, and out-of-range indexes are errors; named selections retain their behavior.

```sh
swys cert inspect --input chain.pem --select 0 -f pem -e base64
```

**--encoding/-e** encodes the complete formatted output. Base64 of PEM includes the PEM delimiters and newlines. Diagnostics stay separate from exported bytes.

JSON always has a **certificates** array containing metadata, complete **pem** strings, and **source** values of **input** or **verified_chain**. Top-level **verification** describes the original leaf and records verified paths as arrays of SHA-256 fingerprints, independently of selection.

Inspection never prints private keys. Successful extraction does not establish trust and does not install the exported CA. Negative verification is reported without failing an otherwise successful export; use **cert verify** when a negative verification result should fail the command.

## Inspect with a custom CA

Inspection uses system trust by default. Use **--ca root.pem** for a CA file, **--ca -** for CA stdin when **--input** names the certificate file, or **--ca-data** for literal CA content. Choose one CA source. Custom anchors replace system roots unless **--system-ca** is also set; your trust store is never modified.

```sh
swys cert inspect --input chain.pem --ca root.pem --format json
```

For response.json containing base64 of a PEM chain in **certificate** and base64 of its CA PEM in **ca**, use jq to extract both values without intermediate certificate files:

```sh
jq -r '.certificate' response.json |
  swys cert inspect --input-encoding base64 \
    --ca-data "$(jq -r '.ca' response.json)" --ca-encoding base64
```

Adjust the field names to match your response. **--ca-encoding** decodes either CA source independently of **--input-encoding**; it defaults to **raw** and supports raw, hex, base64 (also b64), base64url, and base32. Raw PEM needs no outer decoding. CA input accepts a PEM bundle or a single DER certificate. **--ca-data** must be nonempty and never reads a file or stdin.

Custom trust contributes to the verification report and verified-chain selections such as **--select root**. Negative verification remains diagnostic; malformed CA input fails the command before opening output.

## Reference

```sh
swys help cert connect
swys help cert verify
swys cert inspect --help
```
