# Make an HTTP request

Send an HTTP request and write the response body to stdout. URLs without a scheme default to HTTPS. Requests default to GET and do not consume stdin.

## Read a resource

```sh
npc http https://example.com
npc http example.com --select response
```

Send JSON with an explicit method. The --json (-j) flag supplies the body and content type.

```sh
npc http https://api.example.test/items -X POST --json '{"name":"demo"}'
```

For literal bytes, the long data flag and its short form are exact synonyms and still require an explicit method.

```sh
npc http https://api.example.test/items -X POST -d 'literal body'
```

The --connect-timeout (-c) option bounds connection setup and TLS handshaking, with a ten-second default. The --timeout (-t) option bounds the whole request, including upload and response transfer; zero, the default, disables it.

Tracing writes connection and timing diagnostics to stderr, leaving ordinary body output on stdout. TLS verification is enabled by default; use custom trust settings for private services instead of disabling verification when possible.

The default selection is body, and its default format is raw bytes. Select response to include status and headers; its default text format places a blank line before the body. The --format json option works with either selection and stores body bytes as base64 without interpreting application JSON. The --encoding option transforms the complete stdout stream in every supported format. A HEAD request has an empty body by default; select response to see its headers. The --trace option always writes diagnostics to stderr.

## Use encoded TLS credentials

--ca supplies a trust bundle, while --cert and --key supply a matching client identity together. --ca-encoding, --cert-encoding, and --key-encoding independently decode outer credential bytes and default to raw. --input-encoding decodes request bytes; --encoding encodes response output. Credential decoding does not select HTTPS or change verification.

With a local HTTPS service running and an encoded CA bundle:

```sh
npc http https://localhost:8443 --ca ca.pem.b64 --ca-encoding base64
```

An exact - selects original stdin for one credential; ./- names a file. Only one source may own stdin. Request bodies own it with --input -, --json @-, --stdin always, or an automatic non-GET/HEAD request reading non-terminal stdin. A literal or file body, form fields, or --stdin never can leave stdin available for a credential. --data @- is literal text. For example, with the same local service accepting POST requests:

```sh
npc http https://localhost:8443 -X POST --data '@-' --ca - --ca-encoding base64 < ca.pem.b64
```

TLS credentials also apply to HTTPS redirects from an initial HTTP URL. Explicit companion flags require their corresponding source; conflicting stdin sources fail before reads or requests.

For raw application bytes over a transport, use the network family.

```sh
npc help net connect
npc http --help
```
