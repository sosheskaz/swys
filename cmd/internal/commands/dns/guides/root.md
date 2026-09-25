# Resolve DNS names and records

Resolve common names through the operating system or query DNS servers directly. The system resolver is the default for ordinary A, AAAA, and PTR lookups.

## Use the system resolver

```sh
npc dns example.com
npc dns 2001:db8::10 --reverse
```

Ask a particular DNS server by putting its address first. A selected server, transport, or port uses direct DNS and exposes packet-level response details.

```sh
npc dns @1.1.1.1 example.com AAAA
npc dns @1.1.1.1 example.com MX --transport tcp
```

Direct UDP retries a truncated response over TCP. A system lookup may follow operating-system search, hosts-file, or resolver policy that direct DNS bypasses.

## Related command

Use HTTP when the task is an application request rather than a name lookup.

```sh
npc help http
npc dns --help
```
