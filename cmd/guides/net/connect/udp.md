# Exchange one UDP request and response

Read all input as one request datagram, send it, wait for the first response datagram, write that response, and exit. NPC has no send-only mode for this command.

## Send one datagram

The endpoint must already be listening and must send one response.

```sh
printf 'status' | npc net connect udp localhost:9000
```

Input must reach EOF before the datagram is sent; pressing Enter alone does not send interactive input. The wait duration bounds the response wait, and zero waits indefinitely.

This command cannot continue with a second UDP exchange. Use the TCP command only when the peer's protocol also supports a byte-stream transport.

```sh
npc help net connect tcp
npc net connect udp --help
```
