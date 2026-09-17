# Exchange raw bytes

Use the network family when you want to send or receive application bytes yourself. For an HTTP request, start with the HTTP command. To inspect a TLS server's certificates, use certificate connect.

## Choose an operation

- **connect** contacts a remote endpoint and exchanges bytes.
- **listen** accepts one connection, or one UDP request and response.

Then choose TCP, TLS, or UDP. TLS verifies the peer by default on outgoing connections. UDP sends and receives one datagram in each direction.

## Try a local TCP exchange in two terminals

First terminal:

```sh
printf 'hello from server\n' | npc net listen tcp localhost:9000 --close-write
```

Second terminal:

```sh
printf 'hello from client\n' | npc net connect tcp localhost:9000 --close-write
```

Close-write signals the end of each message after stdin ends, so both sides can finish reading without waiting for the drain timeout.

## Next steps

```sh
npc help net connect tls
npc help net listen
npc net --help
```
