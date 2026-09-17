# Match a legacy MD5 checksum

Compute MD5 for compatibility with an existing checksum or protocol. For new uses, start with SHA-256; MD5 is not collision resistant.

## Hash a file or message

Create a small file and save its digest. Hash the same bytes through stdin when comparing with a peer's MD5 value.

```sh
printf 'hello' > message.txt
npc hash md5 --input message.txt --output message.md5
printf 'hello' | npc hash md5
```

The default result is hexadecimal followed by a newline, with no filename attached. An input newline changes the digest. NPC does not automatically verify a checksum file.

## Write a binary digest

Use raw output when a peer needs the 16 digest bytes rather than hexadecimal text. No newline is appended in raw mode.

```sh
npc hash md5 --input message.txt --encoding raw --output digest.bin
```

## Related guides and reference

```sh
npc help hash sha256
npc hash md5 --help
```
