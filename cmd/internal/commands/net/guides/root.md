# Exchange raw bytes

Use the network family when you want to send or receive application bytes yourself. For an HTTP request, start with the HTTP command. To inspect a TLS server's certificates, use certificate connect.

## Choose an operation

Run npc net for the operation reference.

- **connect** contacts a remote endpoint and exchanges bytes.
- **listen** accepts one connection, or one UDP request and response.

Then choose TCP, TLS, or UDP. TLS verifies the peer by default on outgoing connections. UDP sends and receives one datagram in each direction.

## Try a local TCP exchange in two terminals

First terminal:

```sh
printf 'hello from server\n' | npc net listen localhost:9000
```

Second terminal:

```sh
printf 'hello from client\n' | npc net connect localhost:9000
```

Input EOF half-closes each outgoing stream by default, and each command drains its peer until EOF. Sending and receiving are independent by default, so peer EOF does not discard unfinished local input. Explicit --duplex=false restores early exit on peer EOF and can discard outgoing data that has not yet been sent. Use --close-write=false when input EOF must leave the outgoing side open.

This makes local pipelines work without startup sleeps because the connector retries a refused TCP setup within its five-second --connect-timeout (-c):

```sh
printf 'hello, world\n' | npc aes encrypt -k aes.key | npc net connect localhost:4444 | npc net listen localhost:4444 -r | npc aes decrypt -k aes.key
```

## Next steps

```sh
npc help net connect
npc help net listen
npc net --help
```
