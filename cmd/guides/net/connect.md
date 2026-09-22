# Connect to a network endpoint

Open one outbound connection and exchange bytes between stdin and the peer. Choose the transport according to the protocol and trust requirements.

## Choose a transport

- **tcp** exchanges a byte stream without encryption.
- **tls** exchanges a verified encrypted byte stream.
- **udp** sends one request datagram and waits for one response datagram.

For HTTP, use the HTTP command so request framing, redirects, content decoding, and status handling are managed for you.

## Inspect a local TCP service

The connector retries a refused TCP connection within its five-second setup timeout, so a local listener may start shortly afterward.

```sh
printf 'status\n' | npc net connect tcp localhost:9000
```

The setup timeout covers address resolution, connection, and the TLS handshake. It does not time an established byte stream; use an external process deadline when the whole exchange needs a fixed limit.

## Next steps

```sh
npc help net connect tls
npc help http
npc net connect --help
```
