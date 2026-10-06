# Create a test certificate

Create a minimum-viable X.509 certificate for local tests and development. Supply an existing private key, or issue a certificate from a CSR using a local issuer. The default direct-key operation creates a self-signed leaf valid for 30 days.

With --output, SwYS reads and validates the selected key and issuer artifacts and prepares the complete certificate before opening the destination. Artifact read, validation, or certificate creation failures leave that existing file unchanged. Shell redirection opens its destination before SwYS runs.

## Create a localhost identity

Start in a fresh local directory and keep the private keys out of shared fixtures and source control.

```sh
umask 077
swys cert keygen > leaf-key.pem
swys cert create --key leaf-key.pem --dns localhost > leaf-cert.pem
swys cert inspect < leaf-cert.pem
```

## Sign the identity with a test CA

Use the leaf key above, then create a separate CA key and certificate. The leaf names localhost; the CA signs that identity without taking ownership of its private key.

```sh
swys cert keygen > ca-key.pem
swys cert create --ca --key ca-key.pem --subject 'CN=Local Test CA' > ca.pem
swys cert create --key leaf-key.pem --dns localhost --issuer-cert ca.pem --issuer-key ca-key.pem > signed-leaf.pem
swys cert inspect --format text < signed-leaf.pem
```

SwYS **does not** install generated authorities into a trust store. Select the test CA explicitly in the client or an isolated test trust store.

Keep both private keys out of shared fixtures and source control. Share ca.pem with test clients that need to trust the issued certificate.

## Issue a certificate from a request

Use the leaf key and local issuer files created above. The CSR supplies the leaf's public key and identity; --csr issuance needs the issuer certificate and key, not the leaf's --key.

```sh
swys cert csr --key leaf-key.pem --dns localhost > leaf.csr
swys cert create --csr leaf.csr --issuer-cert ca.pem --issuer-key ca-key.pem > csr-leaf.pem
swys cert verify --ca ca.pem --hostname localhost < csr-leaf.pem
```

## Read independently encoded artifacts

Use **--key-encoding**, **--csr-encoding**, **--issuer-cert-encoding**, and **--issuer-key-encoding** to describe each artifact's outer byte encoding. Each defaults to **raw**; supported codecs are raw, hex, base64 (also b64), base64url, and base32. PEM's internal Base64 is part of PEM and needs no outer codec.

This complete local issuance workflow stores the request and issuer certificate as Base64 and the issuer key as hex:

```sh
umask 077
swys cert keygen --encoding base64 --output encoded-leaf-key.b64
swys cert csr --key encoded-leaf-key.b64 --key-encoding base64 --dns localhost --encoding base64 --output encoded-leaf.csr.b64
swys cert keygen --encoding hex --output encoded-ca-key.hex
swys cert create --ca --key encoded-ca-key.hex --key-encoding hex --subject 'CN=Encoded Test CA' --encoding base64 --output encoded-ca.b64
swys cert create --csr encoded-leaf.csr.b64 --csr-encoding base64 --issuer-cert encoded-ca.b64 --issuer-cert-encoding base64 --issuer-key encoded-ca-key.hex --issuer-key-encoding hex --output encoded-leaf.pem
swys cert verify --input encoded-leaf.pem --ca encoded-ca.b64 --ca-encoding base64 --hostname localhost
```

At most one artifact may use **-**. **--input** redirects that operand from a file. For that operand, choose either its companion encoding flag or **--input-encoding**; explicitly setting both is rejected, even for raw or identical codecs. Encodings on other named files remain independent. An explicitly selected companion codec requires a nonempty corresponding artifact source, and invalid selections fail before reading artifacts or opening output.

## Related guides

```sh
swys help cert keygen
swys help cert csr
swys help cert inspect
swys cert create --help
```
