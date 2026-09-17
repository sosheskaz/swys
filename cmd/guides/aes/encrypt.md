# Encrypt a message with AES

Encrypt plaintext with AES-GCM by default. Supply a base64 key directly or read raw key bytes from a file. Binary ciphertext goes to stdout unless an output file or encoding is selected.

## Encrypt with a key file

Create the key once, then protect a message.

```sh
npc key generate aes256 --output key.bin
printf 'deploy at 09:00' | npc aes encrypt --keyfile key.bin --output message.gcm
```

Additional authenticated data is checked during decryption but is not stored in the ciphertext. The decrypting side must supply the same value.

```sh
printf 'payload' | npc aes encrypt --keyfile key.bin --aad production --output payload.gcm
```

Use CBC only for an existing compatibility requirement. CBC does **not** authenticate ciphertext.

## Reference

```sh
npc aes encrypt --help
```
