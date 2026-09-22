# Accept one TCP connection

Listen on a local TCP address, accept one client, and relay bytes between stdin, stdout, and that connection. The command exits after that exchange.

## Return one response

Start this command before connecting a client from another terminal.

```sh
printf 'ready\n' | npc net listen tcp localhost:9000
```

Input EOF half-closes the outgoing side by default, then NPC drains the peer until EOF. Peer EOF normally stops blocked local input; duplex mode keeps sending until local EOF or cancellation. Omit the host to listen on all available local IPv4 and IPv6 addresses; specify a host to limit exposure.

Use the TLS listener when clients require encryption.

```sh
npc help net listen tls
npc net listen tcp --help
```
