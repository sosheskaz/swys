# Resolve DNS names and records

Resolve common names through the operating system or query DNS servers directly. The system resolver is the default for ordinary A, AAAA, and PTR lookups.

Use --output to save the lookup result and --mode to select file permissions. DNS reads its query from command arguments, so an explicit --input is an error.

The --timeout (-t) option covers the whole lookup, with a ten-second default; zero disables it.

## Use the system resolver

```sh
npc dns example.com
npc dns 2001:db8::10 --reverse
```

Ask a particular DNS server by putting its address first. A selected server, transport, or port uses direct DNS and exposes packet-level response details.

```sh
npc dns @1.1.1.1 example.com AAAA
npc dns @tcp://1.1.1.1 example.com MX --select values
```

Direct UDP retries a truncated response over TCP. A system lookup may follow operating-system search, hosts-file, or resolver policy that direct DNS bypasses.

## Choose output

The default selection, **result**, includes the resolver, response details when available, and answers. Choose **--select values** for answer values alone. The default **--format text** prints readable lines; **--format json** prints the complete result object or an array of selected values. An empty values selection prints no text bytes or an empty JSON array. TXT values retain DNS zone-file quoting and escaping.

**--encoding** (or **-e**) transforms the complete formatted output, including its final newline. The default **raw** encoding leaves it unchanged. For example, encode the JSON values array as Base64:

```sh
npc dns @1.1.1.1 example.com TXT --select values --format json --encoding base64
```

Unsupported output encodings and invalid **--mode** values are rejected before a DNS query. **--mode** requires **--output**.

## Use encoded TLS credentials

For DNS over TLS or HTTPS, --ca supplies a trust bundle; --cert and --key supply a matching client identity together. Each source has an independent raw-default companion: --ca-encoding, --cert-encoding, and --key-encoding. These decode the outer source bytes before certificate or key parsing. --encoding still selects lookup output encoding.

With a Base64-encoded CA bundle for a local encrypted resolver already running:

```sh
npc dns @https://localhost:8443/dns-query example.test --ca ca.pem.b64 --ca-encoding base64
```

An exact - selects original stdin for one credential; ./- names a file. DNS has no payload stdin, so one credential may use it. Multiple credential stdin sources are rejected before reading. An explicit companion flag requires its corresponding source, and TLS controls require a TLS or HTTPS endpoint.

## Related command

Use HTTP when the task is an application request rather than a name lookup.

```sh
npc help http
npc dns --help
```
