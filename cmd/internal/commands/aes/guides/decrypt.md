# Decrypt an AES message

Decrypt ciphertext with the same key, cipher mode, and additional authenticated data used for encryption. Default AES-GCM-HKDF streaming releases plaintext one authenticated segment at a time. If a later segment fails, earlier verified plaintext can remain on stdout or in the output file; the command returns an error and releases no bytes from the failed segment.

## Decrypt from a file

Prerequisite: create key.bin and message.gcm with the encryption guide's key-file workflow.

```sh
npc aes decrypt --keyfile key.bin --input message.gcm --output message.txt
```

For a stream that used additional authenticated data, repeat that exact value.

```sh
npc aes decrypt --keyfile key.bin --aad production --input payload.gcm
```

Existing single-message GCM ciphertext needs --raw. There is no format detection or fallback. Raw mode verifies the whole message before releasing plaintext and retains a 64 MiB limit. New streams carry their chunk size in the header; decryption has no --chunk-size flag. AES-192 keys are no longer supported.

Select CBC explicitly only when the ciphertext uses NPC's CBC framing. CBC cannot prove that the key or plaintext is correct.

## Related guide and reference

```sh
npc help aes encrypt
npc aes decrypt --help
```
