# Decrypt an AES message

Select the ciphertext's wire format explicitly. OpenPGP RFC 9580 AES-GCM is the default; use --wire-format tink for a native Tink AES-GCM-HKDF stream. A keyfile may contain a raw key or cleartext Tink JSON or binary keyset; its format is detected from its contents by default. Use --key-format to select one explicitly.

## Decrypt OpenPGP from a file

Prerequisite: create key.bin and message.pgp with the encryption guide's raw-key workflow.

```sh
npc aes decrypt --keyfile key.bin --input message.pgp --output message.txt
```

For OpenPGP with a keyset, decryption uses the enabled primary key by default. Supply --key-id for ciphertext encrypted with another enabled key, such as an older key after rotation. OpenPGP does not try other keys. Decryption reads the chunk size from the packet. It accepts ZIP, ZLIB, and BZip2 compression up to four nested layers. Before opening output, it looks for the literal data header in about 4 MiB of decrypted data and of each decompressed layer, with ciphertext rounded up to whole chunks, and rejects messages that need more.

## Decrypt Tink ciphertext

Prerequisite: create payload.tink with the encryption guide's Tink workflow. Repeat the exact --aad value used at encryption. Tink keysets use enabled keys for decryption.

```sh
npc aes decrypt --wire-format tink --keyfile key.bin --aad production --input payload.tink
```

Decryption releases authenticated chunks as they complete. A later authentication or structure failure may leave earlier verified plaintext in the output, and the command returns an error. It checks the final tag and end of input before success. Historical NPC-specific streams, raw GCM, and CBC require an older NPC binary.

## Reference

```sh
npc aes decrypt --help
```
