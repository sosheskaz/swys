# Accept one TLS connection

Listen for one TLS client using a supplied certificate chain and private key, then relay raw application bytes. The command exits after that exchange.

## Serve with a test identity

Prerequisite: create server-cert.pem and server-key.pem for the listen address, then start the listener before the client.

```sh
printf 'ready\n' | npc net listen tls localhost:9443 --cert server-cert.pem --key server-key.pem --close-write
```

Client certificates are optional by default. Supplying a client CA bundle requires and verifies a client certificate; adding system-ca combines system roots with that bundle.

ALPN selection does not transform application bytes. Omit the host only when listening on every local interface is intended.

## Related guide

```sh
npc help cert create
npc net listen tls --help
```
