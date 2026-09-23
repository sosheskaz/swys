# Exchange bytes over TCP

Connect to a TCP endpoint and relay stdin to the connection while writing received bytes to stdout. NPC does not add application framing.

## Send a request that ends at stdin EOF

The endpoint must understand the bytes you send. The connector can retry a refused setup briefly when the listener is still starting.

```sh
printf 'hello\n' | npc net connect tcp localhost:9000
```

Input EOF half-closes the outgoing side by default, then NPC drains the peer until EOF. A positive wait duration limits that drain and returns an error if it expires; zero is unlimited. Peer EOF waits for unfinished local input by default. Explicit --duplex=false exits on peer EOF and can discard outgoing data that has not yet been sent. Use --close-write=false when input EOF must leave the outgoing side open.

TCP setup defaults to five seconds and retries refused connections within that budget. It does not retry an established connection or replay application data.

Use TLS when the peer requires encryption and identity verification.

```sh
npc help net connect tls
npc net connect tcp --help
```
