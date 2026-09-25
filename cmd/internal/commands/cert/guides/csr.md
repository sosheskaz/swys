# Create a certificate signing request

Create a PKCS #10 request from an existing private key. The request contains the chosen subject and requested DNS or IP subject alternative names; NPC does not submit or sign it.

## Request a server identity

```sh
npc key generate ed25519 --output server-key.pem
npc cert csr --key server-key.pem --dns service.example.test --output server.csr
```

Send the request to the intended certificate authority using that authority's approved process. Keep the private key local; only the request needs to leave the machine.

Inspect issued certificates after the authority returns them.

```sh
npc help cert inspect
npc cert csr --help
```
