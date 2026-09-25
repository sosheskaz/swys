# Generate a cryptographic key

Generate a supported AES, Ed25519, ECDSA, or RSA key. The algorithm operand determines the key type and size.

## Generate private and public files together

```sh
npc key generate ed25519 --output private.pem --public-out public.pem
```

Use the private key to create a self-signed certificate for a local test service. The certificate contains its public key and the chosen identity; the public.pem file alone is not a certificate.

```sh
npc cert create --key private.pem --dns localhost --output localhost.pem
npc cert inspect --input localhost.pem
```

## Encrypt and recover a message

Generate an AES key once and use that same file for encryption and decryption. These commands use authenticated AES-GCM by default.

```sh
npc key generate aes256 --output key.bin
printf 'deploy at 09:00' | npc aes encrypt --keyfile key.bin --output message.gcm
npc aes decrypt --keyfile key.bin --input message.gcm
```

Keep key.bin for later decryption and store it separately from the ciphertext. Generating another key will not recover messages protected by the old one.

Private output is sensitive. Existing regular files must already have acceptable permissions unless an explicit mode authorizes replacement with another setting.

## Related guides

```sh
npc help key public
npc help cert create
npc help aes
npc key generate --help
```
