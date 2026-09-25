# Make an HTTP request

Send an HTTP request and write the response body to stdout. URLs without a scheme default to HTTPS. Requests default to GET and do not consume stdin.

## Read a resource

```sh
npc http https://example.com
npc http example.com --include
```

Send JSON with an explicit method. The JSON flag supplies the body and content type.

```sh
npc http https://api.example.test/items -X POST --json '{"name":"demo"}'
```

For literal bytes, the long data flag and its short form are exact synonyms and still require an explicit method.

```sh
npc http https://api.example.test/items -X POST -d 'literal body'
```

Tracing writes connection and timing diagnostics to stderr, leaving ordinary body output on stdout. TLS verification is enabled by default; use custom trust settings for private services instead of disabling verification when possible.

For raw application bytes over a transport, use the network family.

```sh
npc help net connect
npc http --help
```
