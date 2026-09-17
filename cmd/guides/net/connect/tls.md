# Exchange bytes over verified TLS

Connect to a TLS endpoint and relay raw application bytes. Server certificates and hostnames are verified by default.

## Send bytes to a TLS service

The endpoint must already be listening and must understand the application bytes.

```sh
printf 'hello\n' | npc net connect tls service.example.test:443 --close-write
```

Use a private CA bundle when the service is not rooted in the system trust store.

```sh
printf 'hello\n' | npc net connect tls service.example.test:443 --ca test-ca.pem --close-write
```

The CA flag replaces system roots unless system-ca is also selected. Insecure mode disables certificate and hostname verification and is intended only for controlled diagnostics. ALPN selection does not transform payload bytes.

Inspect presented certificates separately when troubleshooting trust.

```sh
npc help cert connect
npc net connect tls --help
```
