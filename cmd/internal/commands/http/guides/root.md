# Make an HTTP request

Send an HTTP request and write the response body to stdout. URLs without a scheme default to HTTPS. A bare URL uses GET and does not consume stdin.

Response selection accepts **--format text|plain|json**. Text styles status and header names on supported terminals; plain uses the same wire-like layout without generated ANSI. Header names sort deterministically and repeated values keep their order. Body bytes remain unchanged after the blank separator. **--style auto|rich|plain** also controls grouped trace diagnostics; **--format plain** takes precedence. The default body selection stays raw bytes.

## Read a resource

```sh
swys http https://example.com
swys http example.com --select response
```

## Send a body

An explicit body implies POST unless --method (-X) selects another method. Body selection includes --data (even an empty value), --json (-j), --input (-i), form/file fields, and --stdin always. The --stdin auto or never policy alone leaves a bare request as GET.

The --json (-j) flag supplies the body and content type.

```sh
swys http https://api.example.test/items --json '{"name":"demo"}'
```

Use an explicit method to override POST, including GET, HEAD, or a custom method whose spelling SwYS preserves. For example, replace a resource with literal bytes:

```sh
swys http https://api.example.test/items -X PUT -d 'literal body'
```

The --connect-timeout (-c) option bounds connection setup and TLS handshaking, with a ten-second default. The --timeout (-t) option bounds the whole request, including upload and response transfer; zero, the default, disables it.

Tracing writes connection and timing diagnostics to stderr, leaving ordinary body output on stdout. TLS verification is enabled by default; use custom trust settings for private services instead of disabling verification when possible. --insecure-no-verify disables only verification, while --insecure enables every insecure carve-out, including cleartext credentials.

## Authenticate

--auth-bearer-file, --auth-bearer-env, and --auth-bearer send the token alone as Authorization: Bearer. The matching --auth-basic forms take USER:PASSWORD and send Basic credentials. Prefer the file and environment forms; literal values are visible to other local users in process listings and shell history. One trailing line ending is removed from a credential file.

```sh
swys http https://api.example.test/items --auth-bearer-file token.txt
swys http https://api.example.test/items --auth-basic-env API_CREDENTIALS
```

These flags own the Authorization header, so an Authorization --header (-H) or credentials in the URL are rejected alongside them. Credentials require HTTPS: an http:// URL also needs --insecure-cleartext-auth or the --insecure umbrella. A redirect chain drops the credential once it leaves HTTPS or reaches a host other than the original host or its subdomains. An exact - reads the credential file from stdin when no body or TLS credential owns it.

## Compose the response

Hash the response body without saving it first:

```sh
swys http https://example.com/download | swys hash sha256
```

The default selection is body, and its default format is raw bytes. Select response to include status and headers; its default text format places a blank line before the body. The --format json option works with either selection and stores body bytes as base64 without interpreting application JSON. The --encoding option transforms the complete stdout stream in every supported format. A HEAD request has an empty body by default; select response to see its headers. The --trace option always writes diagnostics to stderr.

## Use encoded TLS credentials

--ca supplies a trust bundle, while --cert and --key supply a matching client identity together. --ca-encoding, --cert-encoding, and --key-encoding independently decode outer credential bytes and default to raw. --input-encoding decodes request bytes; --encoding encodes response output. Credential decoding does not select HTTPS or change verification.

With a local HTTPS service running and an encoded CA bundle:

```sh
swys http https://localhost:8443 --ca ca.pem.b64 --ca-encoding base64
```

An exact - selects original stdin for one credential; ./- names a file. Only one source may own stdin. Request bodies own it with --input -, --json @-, --stdin always, or an automatic non-GET/HEAD request reading non-terminal stdin. A literal or file body, form fields, or --stdin never can leave stdin available for a credential. --data @- is literal text. For example, with the same local service accepting POST requests:

```sh
swys http https://localhost:8443 -X POST --data '@-' --ca - --ca-encoding base64 < ca.pem.b64
```

TLS credentials also apply to HTTPS redirects from an initial HTTP URL. Explicit companion flags require their corresponding source; conflicting stdin sources fail before reads or requests.

For raw application bytes over a transport, use the network family.

```sh
swys help net connect
swys http --help
```
