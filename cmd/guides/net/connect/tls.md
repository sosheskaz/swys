# Exchange bytes over verified TLS

Connect to a TLS endpoint and relay raw application bytes. Server certificates and hostnames are verified by default.

## Send bytes to a TLS service

The endpoint must understand the application bytes. The connector can retry a refused TCP setup briefly when the listener is still starting.

```sh
printf 'hello\n' | npc net connect tls service.example.test:443
```

Use a private CA bundle when the service is not rooted in the system trust store.

```sh
printf 'hello\n' | npc net connect tls service.example.test:443 --ca test-ca.pem
```

The CA flag replaces system roots unless system-ca is also selected. Insecure mode disables certificate and hostname verification and is intended only for controlled diagnostics. ALPN selection does not transform payload bytes.

Input EOF half-closes the outgoing side and response draining is unlimited by default. Duplex mode keeps sending after peer EOF. The five-second setup timeout includes TCP retries after connection refusal and one TLS handshake; established streams and application data are never retried.

Inspect presented certificates separately when troubleshooting trust.

```sh
npc help cert connect
npc net connect tls --help
```
