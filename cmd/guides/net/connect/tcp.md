# Exchange bytes over TCP

Connect to a TCP endpoint and relay stdin to the connection while writing received bytes to stdout. NPC does not add application framing.

## Send a request that ends at stdin EOF

The endpoint must already be listening and must understand the bytes you send.

```sh
printf 'hello\n' | npc net connect tcp localhost:9000 --close-write
```

Close-write half-closes the outgoing side after stdin ends, which helps protocols where EOF terminates a request. The wait duration controls how long NPC drains the peer after local input is finished.

Use TLS when the peer requires encryption and identity verification.

```sh
npc help net connect tls
npc net connect tcp --help
```
