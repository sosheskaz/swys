# Listen for one network exchange

Open a local endpoint, handle one stream connection or UDP request and response, then exit. TCP is the default; select UDP with --udp (-u) or TLS with --tls (-T).

## Choose a protocol

- **tcp** accepts one unencrypted byte stream.
- **udp** receives one request datagram and sends one response datagram.
- **tls** accepts one encrypted stream using a required certificate and private key.

## TCP stream

Start the listener before the client.

```sh
printf 'hello from server\n' | npc net listen localhost:9000
```

Input EOF half-closes sending by default, and response draining is unlimited. Peer EOF waits for unfinished local input by default. --duplex=false exits on peer EOF and may discard unsent input. --recv-only (-r) drains the peer without reading stdin or sending a response; the write half stays open until peer EOF. --wait limits response draining for TCP and TLS. Omit the host to listen on all available local IPv4 and IPv6 addresses; bind to a specific interface when broad exposure is not intended.

## UDP datagram

```sh
printf 'ready' | npc net listen --udp localhost:9000
```

NPC writes the first received request datagram, then reads all decoded input as one response datagram to that peer, including an empty response. Input must reach EOF before sending. --timeout bounds bind resolution and waiting for the first datagram; zero waits indefinitely. UDP listen does not accept --wait, --close-write, --duplex, or --recv-only.

## TLS stream

Create a server certificate and matching private key for the listen address before starting the listener.

```sh
printf 'ready\n' | npc net listen --tls localhost:9443 --cert server-cert.pem --key server-key.pem
```

TLS listener mode requires --cert and --key. Supplying --ca requires and verifies a client certificate; --system-ca combines system roots with that bundle. --alpn advertises application protocols without transforming payload bytes. TLS uses the TCP stream lifecycle and may use --recv-only. Listener setup waits indefinitely by default; a positive --timeout bounds bind, accept, and handshake setup.

NPC loads and validates local TLS CA and identity files before opening the output destination or reading payload bytes. Local credential failures leave an existing output file unchanged. Later network, handshake, or stream failures may leave partial output.

## Next steps

```sh
npc help cert create
npc help net connect
npc net listen --help
```
