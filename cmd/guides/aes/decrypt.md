# Decrypt an AES message

Decrypt ciphertext with the same key, cipher mode, and additional authenticated data used for encryption. GCM authentication completes before plaintext is released.

## Decrypt from a file

Prerequisite: create key.bin and message.gcm with the encryption guide's key-file workflow.

```sh
npc aes decrypt --keyfile key.bin --input message.gcm --output message.txt
```

For a GCM message that used additional authenticated data, repeat that exact value.

```sh
npc aes decrypt --keyfile key.bin --aad production --input payload.gcm
```

Select CBC explicitly only when the ciphertext uses NPC's CBC framing. CBC cannot prove that the key or plaintext is correct.

## Related guide and reference

```sh
npc help aes encrypt
npc aes decrypt --help
```
