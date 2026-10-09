# Connect to a network endpoint

Open one outbound endpoint and exchange bytes between stdin and the peer. TCP is the default; select UDP with --udp (-u) or TLS with --tls (-T).

**--style auto|rich|plain** controls verbose diagnostics on stderr. Auto uses restrained styles on supported terminals; plain emits no generated ANSI controls. TCP and UDP events stay compact, and TLS details are grouped. Payload bytes on stdout are unchanged.

## Choose a protocol

- **tcp** exchanges an unencrypted byte stream.
- **udp** sends one request datagram and waits for the first response datagram.
- **tls** exchanges a verified encrypted byte stream. TLS options require --tls.

For HTTP, use the HTTP command so request framing, redirects, content decoding, and status handling are managed for you.

## TCP stream

Start this listener in the first terminal:

```sh
printf 'ready\n' | swys net listen localhost:9000
```

Connect from the second terminal:

```sh
printf 'status\n' | swys net connect localhost:9000
```

Input EOF half-closes sending by default, then SwYS drains the response until EOF. A positive --wait (-w) limits that drain and returns an error with partial output preserved on expiry; zero waits indefinitely. Peer EOF waits for unfinished local input by default. --duplex=false exits on peer EOF and may discard unsent input. Use --close-write=false when input EOF must leave sending open. The five-second --connect-timeout (-c) covers address resolution and connection retries after refusal; it does not time or replay an established stream.

## UDP datagram

Start this listener before the client, in a separate terminal:

```sh
printf 'ready' | swys net listen --udp localhost:9000
```

Then send one datagram:

```sh
printf 'status' | swys net connect --udp localhost:9000
```

All decoded input becomes one datagram, including empty input. Input must reach EOF before sending; pressing Enter alone does not send it. SwYS writes the first response datagram and exits. The default response wait is five seconds; --wait 0 waits indefinitely. UDP has no send-only mode. The five-second --connect-timeout (-c) covers address resolution and socket setup.

## Verified TLS stream

Use **swys help net listen** to create server-key.pem and server-cert.pem for localhost, then start its TLS listener in the first terminal. Connect from the second terminal, explicitly trusting that test certificate:

```sh
printf 'hello\n' | swys net connect --tls localhost:9443 --ca server-cert.pem
```

Server certificates and hostnames are verified by default. --ca replaces system roots unless --system-ca is also set. --cert and --key supply an optional client identity together. --servername overrides the endpoint host for SNI and verification. --insecure disables verification for controlled diagnostics and cannot be combined with --ca or --system-ca. --alpn advertises application protocols; it does not transform payload bytes. TLS uses the TCP stream lifecycle. Its five-second --connect-timeout (-c) includes the handshake.

SwYS loads and validates local TLS CA and identity files before opening the output destination or reading payload bytes. Local credential failures leave an existing output file unchanged. Later network, handshake, or stream failures may leave partial output.

## Decode credentials separately from payload

--ca-encoding, --cert-encoding, and --key-encoding independently decode the outer bytes of their TLS sources and default to raw. --input-encoding decodes payload bytes; --encoding encodes received output. An explicit companion flag requires its source and --tls.

An exact - selects original stdin for one credential; ./- names a file. Connect normally owns stdin for payload, including with --duplex=false. Select a payload file to leave stdin available for one credential. Multiple stdin owners fail before reads or connection setup.

With a local TLS service running, a hex CA bundle, Base64 client certificate and payload, and Base32 client key:

```sh
swys net connect --tls localhost:9443 --ca - --ca-encoding hex \
  --cert client.pem.b64 --cert-encoding base64 --key client-key.pem.b32 --key-encoding base32 \
  --input request.b64 --input-encoding base64 < ca.pem.hex
```

## Next steps

```sh
swys help cert connect
swys help net listen
swys net connect --help
```
