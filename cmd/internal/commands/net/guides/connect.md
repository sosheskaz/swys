# Connect to a network endpoint

Open one outbound endpoint and exchange bytes between stdin and the peer. TCP is the default; select UDP with --udp (-u) or TLS with --tls (-T).

## Choose a protocol

- **tcp** exchanges an unencrypted byte stream.
- **udp** sends one request datagram and waits for the first response datagram.
- **tls** exchanges a verified encrypted byte stream. TLS options require --tls.

For HTTP, use the HTTP command so request framing, redirects, content decoding, and status handling are managed for you.

## TCP stream

```sh
printf 'status\n' | npc net connect localhost:9000
```

Input EOF half-closes sending by default, then NPC drains the response until EOF. A positive --wait (-w) limits that drain and returns an error with partial output preserved on expiry; zero waits indefinitely. Peer EOF waits for unfinished local input by default. --duplex=false exits on peer EOF and may discard unsent input. Use --close-write=false when input EOF must leave sending open. The five-second --connect-timeout (-c) covers address resolution and connection retries after refusal; it does not time or replay an established stream.

## UDP datagram

```sh
printf 'status' | npc net connect --udp localhost:9000
```

All decoded input becomes one datagram, including empty input. Input must reach EOF before sending; pressing Enter alone does not send it. NPC writes the first response datagram and exits. The default response wait is five seconds; --wait 0 waits indefinitely. UDP has no send-only mode. The five-second --connect-timeout (-c) covers address resolution and socket setup.

## Verified TLS stream

```sh
printf 'hello\n' | npc net connect --tls service.example.test:443 --ca test-ca.pem
```

Server certificates and hostnames are verified by default. --ca replaces system roots unless --system-ca is also set. --cert and --key supply an optional client identity together. --servername overrides the endpoint host for SNI and verification. --insecure disables verification for controlled diagnostics and cannot be combined with --ca or --system-ca. --alpn advertises application protocols; it does not transform payload bytes. TLS uses the TCP stream lifecycle. Its five-second --connect-timeout (-c) includes the handshake.

NPC loads and validates local TLS CA and identity files before opening the output destination or reading payload bytes. Local credential failures leave an existing output file unchanged. Later network, handshake, or stream failures may leave partial output.

## Next steps

```sh
npc help cert connect
npc help net listen
npc net connect --help
```
