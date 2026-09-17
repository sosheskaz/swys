# Receive one UDP request and send one response

Bind a UDP endpoint, receive the first request datagram, read all stdin as one response datagram, send it to that peer, and exit.

## Serve one response

Start this command before the client. Stdin EOF determines when the response datagram is ready.

```sh
printf 'ready' | npc net listen udp localhost:9000
```

The timeout bounds waiting for the request; zero waits indefinitely. Omit the host only when listening on every local interface is intended.

The connecting client must expect one response.

```sh
npc help net connect udp
npc net listen udp --help
```
