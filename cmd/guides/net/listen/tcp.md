# Accept one TCP connection

Listen on a local TCP address, accept one client, and relay bytes between stdin, stdout, and that connection. The command exits after that exchange.

## Return one response

Start this command before connecting a client from another terminal.

```sh
printf 'ready\n' | npc net listen tcp localhost:9000
```

Input EOF half-closes the outgoing side by default, then NPC drains the peer until EOF. Peer EOF waits for unfinished local input by default. Explicit --duplex=false exits on peer EOF and can discard outgoing data that has not yet been sent. Use --recv-only (-r) to drain the request without reading stdin or sending a response; the write half stays open until peer EOF. Omit the host to listen on all available local IPv4 and IPv6 addresses; specify a host to limit exposure.

Use the TLS listener when clients require encryption.

```sh
npc help net listen tls
npc net listen tcp --help
```
