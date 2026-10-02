# Make an HTTP request

Send an HTTP request and write the response body to stdout. URLs without a scheme default to HTTPS. Requests default to GET and do not consume stdin.

## Read a resource

```sh
npc http https://example.com
npc http example.com --select response
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

The default selection is body, and its default format is raw bytes. Select response to include status and headers; its default text format places a blank line before the body. The --format json option works with either selection and stores body bytes as base64 without interpreting application JSON. The --encoding option transforms the complete stdout stream in every supported format. A HEAD request has an empty body by default; select response to see its headers. The --trace option always writes diagnostics to stderr.

For raw application bytes over a transport, use the network family.

```sh
npc help net connect
npc http --help
```
