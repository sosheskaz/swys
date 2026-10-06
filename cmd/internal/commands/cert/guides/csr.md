# Create a certificate signing request

Create a PKCS #10 request from an existing private key. The request contains the chosen subject and requested DNS or IP subject alternative names. This command does not contact a certificate authority or issue a certificate; use swys cert create --csr to issue one locally.

With --output, SwYS reads and validates the key and prepares the complete request before opening the destination. Key read, validation, or request creation failures leave that existing file unchanged. Shell redirection opens its destination before SwYS runs.

## Request a server identity

Start in a fresh local directory and keep the private key local.

```sh
umask 077
swys cert keygen > server-key.pem
swys cert csr --key server-key.pem --dns service.example.test > server.csr
```

Send the request to the intended certificate authority using that authority's approved process. Keep the private key local; only the request needs to leave the machine.

## Issue locally with a test CA

Use server.csr from above, then create a separate local issuer key and CA certificate. Issuance uses the request's public key and identity; do not supply the server's --key with --csr.

```sh
swys cert keygen > ca-key.pem
swys cert create --ca --key ca-key.pem --subject 'CN=Local Test CA' > ca.pem
swys cert create --csr server.csr --issuer-cert ca.pem --issuer-key ca-key.pem > server-cert.pem
swys cert verify --ca ca.pem --hostname service.example.test < server-cert.pem
```

This does not install the CA in a trust store. Keep both private keys local and select ca.pem explicitly when trusting this test identity.

## Read an encoded private key

**--key-encoding** describes the key's outer byte encoding and defaults to **raw**. Supported codecs are raw, hex, base64 (also b64), base64url, and base32. PEM's internal Base64 needs no outer codec.

```sh
umask 077
swys cert keygen --encoding base64url --output encoded-server-key.b64url
swys cert csr --key encoded-server-key.b64url --key-encoding base64url --dns service.example.test --output encoded-server.csr
```

Use **--key -** to read stdin, or pair it with **--input** to read a selected file. Choose either **--key-encoding** or **--input-encoding** for that stream; explicitly setting both is rejected, including raw or identical codecs. A companion codec requires a nonempty key source. Invalid selections fail before reading the key or opening output.

## Related guides

```sh
swys help cert create
swys help cert inspect
swys cert csr --help
```
