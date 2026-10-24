# Inspect certificates from a file or stdin

Read a PEM certificate bundle or one DER certificate and report identity, validity dates, key usage, CA status, and fingerprints. By default, all supplied certificates are displayed as text, in input order. Bundles may contain unrelated certificates; inspection does not verify trust, certificate purpose, or chain order.

Human reports default to **text**, with restrained styling on supported terminals. **--format plain** keeps the same layout without generated ANSI controls. **--style auto|rich|plain** overrides human text styling; the plain format takes precedence. Values remain intact and use terminal wrapping. File and encoded output default to plain presentation.


## Inspect or export certificates

The examples below require a certificate or bundle in chain.pem. Root and numeric selections require a complete leaf-first signature chain, including its self-signed CA. Use **swys help cert create** to create a local test identity, or export a reachable endpoint's certificates with **cert connect**.

```sh
swys cert inspect -i chain.pem --format text
swys cert inspect -i chain.pem --format json
swys cert inspect -i chain.pem --select leaf -f pem -o server.pem
swys cert inspect -i chain.pem --select root -f pem -e base64
```

PEM and DER are recognized automatically. Use **--input-encoding** to decode wrapped certificate bytes before parsing; the default **raw** reads them unchanged.

```sh
swys cert inspect -i certificate.der --format json
swys cert inspect -i chain.pem.b64 --input-encoding base64 --format json
```

For a reachable TLS endpoint, decode an encoded certificate export directly:

```sh
swys cert connect api.example.com:443 --select leaf -f pem -e base64 | swys cert inspect --input-encoding base64
```

The default **text** format displays detailed certificate metadata, validity dates, key usage, CA status, and fingerprints.

**--select leaf|chain|fullchain|root** (or **-s**) chooses the certificate material independently of **--format text|plain|json|pem**. **leaf** selects the first supplied certificate; **chain** excludes the first certificate; **fullchain** preserves all supplied certificates. These positional selections work for unrelated bundles. **root** exports the supplied self-signed CA only when all supplied certificates form a complete leaf-first signature chain. Unavailable selections return an error and preserve existing output files.

A non-negative integer selects one certificate from a complete supplied signature chain in root-to-leaf order: **0** is the root, **1** is the next certificate toward the leaf, and **n-1** is the leaf for a chain of **n** certificates. Missing roots, unrelated certificates, broken links, incorrect order, and out-of-range indexes are selection errors. Signature checks used for root and numeric selection do not establish trust or check validity dates or certificate purpose. Inspection never discovers missing roots through system trust.

```sh
swys cert inspect -i chain.pem --select 0 -f pem -e base64
```

**--encoding/-e** encodes the complete formatted output. Base64 of PEM includes the PEM delimiters and newlines. Diagnostics stay separate from exported bytes.

JSON always has a **certificates** array containing metadata, complete **pem** strings, and **source** values of **input**. It has no verification result. Raw C1 and bidirectional formatting controls in its strings, such as certificate names, are written as \u escapes; decoding the JSON yields the original values. PEM output contains only the selected certificate bytes, without verification diagnostics.

Inspection never prints private keys. Successful extraction does not establish trust and does not install the exported CA. Expired certificates and certificates with restricted purposes remain inspectable.

## Verify a certificate chain

Use **cert verify** for chain ordering, signatures, trust, validity, certificate purpose, and optional hostname checks. The example below requires a leaf-first chain in chain.pem, its trust anchor in root.pem, and a hostname present in the leaf certificate.

```sh
swys cert verify -i chain.pem --ca root.pem --hostname api.example.test
```

CA options such as **--ca**, **--ca-data**, **--ca-encoding**, and **--system-ca** belong to **cert verify**. A negative verification result produces a report and a nonzero exit status.

## Reference

```sh
swys help cert connect
swys help cert verify
swys cert inspect --help
```
