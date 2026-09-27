# Decrypt an AES message

Select the ciphertext's wire format explicitly. OpenPGP RFC 9580 AES-GCM is the default; use --wire-format tink for a native Tink AES-GCM-HKDF stream. The key may be raw or a cleartext Tink JSON or binary keyset.

## Decrypt OpenPGP from a file

Prerequisite: create key.bin and message.pgp with the encryption guide's raw-key workflow.

```sh
npc aes decrypt --keyfile key.bin --input message.pgp --output message.txt
```

For OpenPGP with a keyset, supply --key-id to select one enabled key. OpenPGP decryption reads the chunk size from the packet. It accepts ZIP, ZLIB, and BZip2 compression up to four nested layers. Before opening output, it looks for the literal data header in about 4 MiB of decrypted data and of each decompressed layer, with ciphertext rounded up to whole chunks, and rejects messages that need more.

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
