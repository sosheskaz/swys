# Match a legacy SHA-1 checksum

Compute SHA-1 for compatibility with an existing checksum or protocol. For new uses, start with SHA-256; SHA-1 is not collision resistant.

## Hash exactly the expected input

Create a small file and save its digest. The stdin example hashes the same bytes without adding a newline.

```sh
printf 'hello' > message.txt
swys hash sha1 < message.txt > message.sha1
printf 'hello' | swys hash sha1
```

The default result is hexadecimal followed by a newline, with no filename attached. SwYS computes the digest; it does not automatically compare it with an expected checksum.

## Match a peer's encoding

Select base64 if the peer represents its SHA-1 digest that way. This changes the digest's representation, not the input bytes or algorithm.

```sh
swys hash sha1 --encoding base64 < message.txt
```

## Related guides and reference

```sh
swys help hash sha256
swys hash sha1 --help
```
