# Listen for one network exchange

Open a local endpoint, handle one connection or UDP request and response, then exit. Choose a transport according to the client and trust setup.

## Choose a transport

- **tcp** accepts one unencrypted byte stream.
- **tls** accepts one encrypted stream using a supplied certificate and private key.
- **udp** receives one request datagram and sends one response datagram from stdin.

## Serve one local TCP response

Start the listener before the client.

```sh
printf 'hello from server\n' | npc net listen tcp localhost:9000
```

Input EOF half-closes the accepted stream and response draining is unlimited by default. Peer EOF waits for unfinished local input by default. Explicit --duplex=false exits on peer EOF and can discard outgoing data that has not yet been sent. Use --recv-only (-r) to drain the peer without reading stdin or sending a response; the listener keeps its write half open until the peer reaches EOF. Omitting the host listens on all available local IPv4 and IPv6 addresses. Bind to a specific interface when broad exposure is not intended.

## Next steps

```sh
npc help net listen tls
npc net listen --help
```
