# Inspect certificates from a file or stdin

Read PEM certificates and report identity, validity, fingerprints, and verification information. By default, all supplied certificates are displayed as text, in input order; verification describes the first certificate.

## Inspect or export certificates

```sh
npc cert inspect --input chain.pem --format text
npc cert inspect --input chain.pem --format json
npc cert inspect --input chain.pem --select leaf -f pem -o server.pem
npc cert inspect --input chain.pem --select root -f pem -e base64
```

The default **text** format displays detailed certificate metadata, validity dates, fingerprints, and certificate verification.

**--select leaf|chain|fullchain|root** chooses the certificate material independently of **--format text|json|pem**. **chain** excludes the first certificate; **fullchain** preserves all supplied certificates without adding roots. **root** exports CA trust anchors from verified chains, or a supplied self-signed CA connected by a leaf-first signature chain when trust verification fails. Multiple verified roots are deduplicated and sorted by SHA-256 fingerprint. Unavailable selections return an error and preserve existing output files.

A non-negative integer selects one certificate from a complete, unambiguous chain in root-to-leaf order: **0** is the root, **1** is the next certificate toward the leaf, and **n-1** is the leaf for a chain of **n** certificates. NPC uses a verified chain when available, otherwise a complete supplied signature chain. Missing roots, multiple distinct verified paths, and out-of-range indexes are errors; named selections retain their behavior.

```sh
npc cert inspect --input chain.pem --select 0 -f pem -e base64
```

**--encoding/-e** encodes the complete formatted output. Base64 of PEM includes the PEM delimiters and newlines. Diagnostics stay separate from exported bytes.

JSON always has a **certificates** array containing metadata, complete **pem** strings, and **source** values of **input** or **verified_chain**. Top-level **verification** describes the original leaf and records verified paths as arrays of SHA-256 fingerprints, independently of selection.

Inspection never prints private keys. Successful extraction does not establish trust and does not install the exported CA. Negative verification is reported without failing an otherwise successful export; use **cert verify** when a negative verification result should fail the command.

## Reference

```sh
npc help cert connect
npc help cert verify
npc cert inspect --help
```
