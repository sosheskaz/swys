# Inspect a TLS server's certificates

Connect to a TLS endpoint and inspect the certificates it presents. Use this to investigate identity, validity, and verification problems.

## Inspect the server certificate

```sh
npc cert connect example.com:443
```

Include the peer-provided chain and more certificate details.

```sh
npc cert connect example.com:443 --chain --format long
```

Save the server certificate as PEM.

```sh
npc cert connect example.com:443 --format pem --output server.pem
```

Inspection retrieves certificates even when verification fails, then reports verification separately. A retrieved certificate is **not** proof that the endpoint is trusted. The peer-provided chain may omit the root.

For application traffic over verified TLS, continue with the network TLS guide.

```sh
npc help net connect
npc cert connect --help
```
