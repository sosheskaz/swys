# Decrypt an AES message

Recover a message with the key or password used to encrypt it. OpenPGP RFC 9580 AES-GCM is the default; select --wire-format tink for a Tink stream. SwYS does not detect the ciphertext format or retry another format after an authentication failure.

## Decrypt OpenPGP from a file

Prerequisite: create key.bin and message.pgp with the encryption guide's raw-key workflow.

```sh
swys aes decrypt --key key.bin --input message.pgp --output message.txt
```

For a pipeline, send the recovered bytes directly to the next command:

```sh
swys aes decrypt --key key.bin --input message.pgp | swys hash sha256
```

## Decrypt with a password

Supply the password used for encryption with --password, --password-env NAME, or --password-command SHELL_COMMAND; the source can differ from encryption. The message stores its Argon2id costs, so decryption has no tuning flags.

```sh
swys aes decrypt --password --input message.pgp --output message.txt
```

## Decrypt Tink ciphertext

Prerequisite: create payload.tink with the encryption guide's Tink workflow. Repeat the exact --aad value used at encryption. Tink keysets use enabled keys for decryption.

```sh
swys aes decrypt --wire-format tink --key key.bin --aad production --input payload.tink
```

## Understand formats and authentication

A key file may contain a raw key or cleartext Tink JSON or binary keyset; its format is detected from its contents by default. Use --key-format to select one explicitly.

For OpenPGP with a keyset, decryption uses the enabled primary key by default. Supply --key-id for ciphertext encrypted with another enabled key, such as an older key after rotation. OpenPGP does not try other keys. Decryption reads the chunk size from the packet. It accepts ZIP, ZLIB, and BZip2 compression up to four nested layers. Before opening output, it looks for the literal data header in about 4 MiB of decrypted data and of each decompressed layer, with ciphertext rounded up to whole chunks, and rejects messages that need more.

Before asking for the password or opening output, decryption rejects Argon2 memory above 256MiB, more than 10 passes, more than 16 lanes, more than 16 password wrappers, or wrappers whose combined memory times passes exceeds 256MiB times 10. There is no override. Only Argon2 wrappers are accepted. A wrong password fails before output is opened.

Decryption releases authenticated chunks as they complete. A later authentication or structure failure may leave earlier verified plaintext in the output, and the command returns an error. It checks the final tag and end of input before success. Historical SwYS-specific streams, raw GCM, and CBC require an older SwYS binary.

## Reference

```sh
swys aes decrypt --help
```
