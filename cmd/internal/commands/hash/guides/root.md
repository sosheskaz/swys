# Compute a digest of bytes

Hash a file or stdin to produce a digest for comparison. Choose the algorithm explicitly; NPC writes only the digest, without a filename or checksum-manifest record.

## Choose an algorithm

- **sha256** computes a SHA-256 digest for common file and payload comparisons.
- **sha512** computes a SHA-512 digest when that algorithm is required.
- **sha1** matches existing SHA-1 checksums for compatibility.
- **md5** matches existing MD5 checksums for compatibility.

Prefer SHA-256 for new uses. MD5 and SHA-1 are compatibility options, not choices for collision-resistant integrity checks. A digest alone does not authenticate who supplied the bytes; compare against an expected value from a trusted source.

## Hash a message or file

Use printf to avoid adding a newline to the input. Every input byte matters.

```sh
printf 'hello' | npc hash sha256
printf 'hello' > message.txt
npc hash sha256 < message.txt > message.sha256
```

The pipe and file invocations hash the same bytes. The output file contains a hexadecimal digest followed by a newline. It is not a manifest for a checksum tool's check mode.

## Hash decoded input

Decode a byte representation before hashing when the input is encoded. This produces the same digest as the message above.

```sh
printf 'aGVsbG8=' | npc hash sha256 --input-encoding base64
```

## Next steps

```sh
npc help hash sha256
npc hash --help
```
