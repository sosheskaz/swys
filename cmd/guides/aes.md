# Encrypt and decrypt with AES

Use the AES family when you already have a symmetric key. AES-GCM is the authenticated default. AES-CBC remains available for compatibility with systems that require it.

## Choose an operation

- **encrypt** protects plaintext with a supplied key.
- **decrypt** opens ciphertext made with the same mode, key, and additional data.

## Start with an authenticated message

```sh
npc key generate aes256 --output key.bin
printf 'secret message' | npc aes encrypt --keyfile key.bin --output message.gcm
npc aes decrypt --keyfile key.bin --input message.gcm
```

Keep the key separate from ciphertext. Reusing a key is normal for GCM, but NPC generates a fresh nonce for each encryption.

## Next steps

```sh
npc help aes encrypt
npc help aes decrypt
npc help key generate
npc aes --help
```
