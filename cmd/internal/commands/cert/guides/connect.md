# Inspect a TLS server's certificates

Retrieve certificates from a TLS endpoint, inspect their details, or export their complete PEM bytes. The default **text** format displays detailed leaf metadata, validity dates, fingerprints, and certificate verification. **--format json|pem** selects structured JSON or complete PEM bytes.

## Export a certificate or CA

Use --output to save the retrieved certificates and --mode to select file permissions. This operation reads the server's certificates, so an explicit --input is an error.

```sh
npc cert connect example.com:443 -f pem -o server.pem
npc cert connect example.com:443 --select chain -f pem -o issuers.pem
npc cert connect example.com:443 --select root -f pem -e base64
```

The last command produces standard, padded Base64 of the complete PEM, including its delimiters and newlines. Verification diagnostics go to stderr, separately from the exported bytes.

**--select** chooses the certificate material. **leaf** selects the first certificate; **chain** selects supplied certificates after the leaf; **fullchain** selects all supplied certificates in their original order. These selections never silently append a missing root. An empty selection is an error.

**root** prefers CA trust anchors from verified chains, including roots the peer omitted. Multiple roots are deduplicated and sorted by SHA-256 fingerprint. If verification fails, NPC can still export a supplied self-signed CA when the supplied leaf-first certificate signatures and CA signing constraints connect the leaf to it. A missing root or an unrelated self-signed certificate produces an error.

A non-negative integer selects one certificate from a complete, unambiguous chain in root-to-leaf order: **0** is the root, **1** is the next certificate toward the leaf, and **n-1** is the leaf for a chain of **n** certificates. NPC uses a verified chain when available, otherwise a complete supplied signature chain. Missing roots, multiple distinct verified paths, and out-of-range indexes are errors; named selections retain their behavior.

```sh
npc cert connect example.com:443 --select 0 -f pem -e base64
```

## Inspect details or use JSON

```sh
npc cert connect example.com:443 --select fullchain -f text
npc cert connect example.com:443 --select root -f json
```

JSON always contains a **certificates** array, with complete **pem** strings, certificate metadata, and **source** values identifying peer-supplied material or a certificate obtained from a verified chain. The top-level **verification** object describes the original leaf, regardless of which certificates were selected. Its **chains** contain leaf-to-anchor SHA-256 fingerprints. **--encoding** wraps the entire formatted output, including JSON when selected.

Inspection retrieves certificates even when verification fails. Successful export is **not** proof that the endpoint or exported CA is trusted; read the separate verification result. NPC does not install trust anchors. PEM export succeeds with a diagnostic when extraction succeeds but verification fails. Retrieval, selection, and formatting failures leave an existing output file untouched.

## Reference

```sh
npc help cert inspect
npc cert connect --help
```
