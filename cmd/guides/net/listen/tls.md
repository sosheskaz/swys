# Accept one TLS connection

Listen for one TLS client using a supplied certificate chain and private key, then relay raw application bytes. The command exits after that exchange.

## Serve with a test identity

Prerequisite: create server-cert.pem and server-key.pem for the listen address, then start the listener before the client.

```sh
printf 'ready\n' | npc net listen tls localhost:9443 --cert server-cert.pem --key server-key.pem
```

Client certificates are optional by default. Supplying a client CA bundle requires and verifies a client certificate; adding system-ca combines system roots with that bundle.

ALPN selection does not transform application bytes. Omit the host only when listening on every local interface is intended.

TLS streams use the same pipe lifecycle as TCP: input EOF half-closes sending, and peer EOF waits for unfinished local input by default. Explicit --duplex=false can discard outgoing data that has not yet been sent. Use --recv-only (-r) to drain the peer without reading stdin or sending application data. Listener setup waits indefinitely by default; a positive timeout bounds bind, accept, and handshake setup.

## Related guide

```sh
npc help cert create
npc net listen tls --help
```
