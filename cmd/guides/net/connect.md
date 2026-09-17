# Connect to a network endpoint

Open one outbound connection and exchange bytes between stdin and the peer. Choose the transport according to the protocol and trust requirements.

## Choose a transport

- **tcp** exchanges a byte stream without encryption.
- **tls** exchanges a verified encrypted byte stream.
- **udp** sends one request datagram and waits for one response datagram.

For HTTP, use the HTTP command so request framing, redirects, content decoding, and status handling are managed for you.

## Inspect a local TCP service

The service must already be listening on the selected port.

```sh
printf 'status\n' | npc net connect tcp localhost:9000 --close-write
```

## Next steps

```sh
npc help net connect tls
npc help http
npc net connect --help
```
