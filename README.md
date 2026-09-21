# npc

[![CI](https://github.com/sosheskaz-systems/npc/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sosheskaz-systems/npc/actions/workflows/ci.yml)

**N**etworking, **P**rotocols, **C**rypto — an operator's tool that makes
wire behavior and cryptographic operations legible, ergonomic, and safe by
default. One static binary replacing manual `openssl`, `netcat`, and ad-hoc
`curl` invocations.

> **Status:** early development, pre-1.0. Command names and flags are still
> settling; expect breaking changes, batched and called out in commit messages.

## Installation

On macOS or Linux, build from a checkout with [mise](https://mise.jdx.dev) installed. This
repository is currently private; cloning requires GitHub access to it and an
authenticated Git client.

```fish
git clone https://github.com/sosheskaz-systems/npc.git
cd npc
mise trust
mise install
mise run build:dev
./npc --help
```

The build writes `npc` into the checkout. Put the binary in a directory on your
`PATH` to use the `npc` commands below, or invoke it by its path. Runtime use
does not require mise. The shell examples use fish.

## Quick start

Run these examples in a scratch directory with new output paths. Generate and
inspect a key without printing its private bytes:

```fish
npc key generate ed25519 --output private.pem --public-out public.pem
npc key inspect --input public.pem --format json
```

Create and inspect a self-signed development certificate using that key:

```fish
npc cert create --dns localhost --key private.pem --output certificate.pem
npc cert inspect --input certificate.pem --format long
npc cert verify --input certificate.pem --ca certificate.pem --hostname localhost
npc cert match --cert certificate.pem --key private.pem
```

Encrypt and decrypt a small message with the default authenticated AES-GCM
mode. Keep `aes.key` private:

```fish
npc key generate aes256 --output aes.key
printf 'hello\n' | npc aes encrypt --keyfile aes.key --output message.gcm
npc aes decrypt --keyfile aes.key --input message.gcm
```

For local transport examples, see the [TCP and TLS walkthrough](#raw-tcp-and-tls-walkthrough).
See [key handling](#key-lifecycle-walkthrough), [certificate creation](#certificate-creation-walkthrough),
and [AES usage](#aes-quick-start) for flags and output-file behavior.

Resolve a host through the system resolver, or inspect a record from a specific
DNS server:

```fish
npc dns example.com
npc dns @192.0.2.53 example.com MX --short
```

## Guides and reference help

Use `npc help` for a curated starting guide or add a command path to focus on a
task:

```fish
npc help
npc help net connect tls
npc help x509 connect
```

Guide paths accept command aliases and display canonical command names. Use
`npc --help` or `npc <command path> --help` for the generated command, argument,
flag, alias, and default reference. Bare `npc` and non-runnable branches retain
their compact reference output with a pointer to the corresponding guide;
runnable leaves still enforce their required arguments.

When stdout is a terminal, a nonempty `PAGER` pages guides. Redirects and
external pipelines bypass it. `--no-pager` also bypasses it, while `--rich` and
`--plain` override automatic rendering independently of pager selection:

```fish
env PAGER='less -R' npc help net --rich
npc help net --rich | less -R
npc help net --no-pager
```

`PAGER` is parsed as an executable plus quoted arguments without shell
evaluation; use a wrapper script for pipelines, expansions, or redirections.
Rich guides use clickable link labels; plain guides include visible URLs. Use
`--plain` if your terminal or pager does not support terminal hyperlinks.
Prose wraps at the smaller of the terminal width and 80 columns, or 80 columns
when redirected. Code lines and long tokens remain intact.
The binary embeds every guide and does not require a checkout or network access.
Contributors should follow the [help guide authoring standard](docs/help-authoring.md).

## Commands today

```
npc aes encrypt|decrypt            # AES-GCM default; explicit AES-CBC compatibility
npc key generate <algorithm>       # generate a key with an explicit algorithm
npc key public|inspect|convert     # consume a self-describing key
npc cert create|csr                # mint test identities and certificate requests
npc cert inspect|connect           # certificate inspection and TLS probing
npc cert verify|match              # offline trust and public-key checks
npc dns [@server] name [type]      # system resolution or a direct DNS query
npc hash sha256|sha512|sha1|md5   # stream one input into an explicit digest
npc grpc HOST:PORT                 # discover services and protobuf schemas
npc http URL [-X METHOD]          # GET by default; --method selects any HTTP method
npc net connect tcp|tls|udp host:port # exchange raw bytes over TCP, TLS, or UDP
npc net listen tcp|tls|udp [host:]port # serve one TCP, TLS, or UDP exchange
```

Use `npc help [command path]` for task guidance and `npc --help` or
`npc <noun> <verb> --help` for available flags. The
[product direction](#product-direction-and-roadmap) below also discusses commands
that are not implemented yet.

### DNS lookups

`npc dns name [type]` uses the system resolver and defaults to an A lookup.
System mode supports A, AAAA, and PTR records. Use `-x`/`--reverse` with an IP
address as a convenient PTR form:

```fish
npc dns example.com
npc dns example.com AAAA --format json
npc dns 192.0.2.10 --reverse --short
```

System resolution intentionally exposes only the data returned by Go's
`net.Resolver`. Text output marks the responding server, DNS status/header
fields, and TTLs as unavailable; JSON represents those fields as `null`. It
does not synthesize packet metadata or silently switch to a direct DNS query.
The release build uses `CGO_ENABLED=0`. With the pinned Go 1.27 toolchain,
Darwin still reaches the operating system resolver through its system lookup
path, while Linux and FreeBSD use Go's built-in resolver and therefore do not
provide every NSS-style lookup source.

An `@server` or `--port` selects direct DNS. `--resolver dns` selects configured
nameservers over UDP without an explicit endpoint. Direct endpoints use
`@host[:port]` or a transport scheme: `@udp://`, `@tcp://`, `@tls://`, and
`@https://`. Their default ports are 53, 53, 853, and 443. UDP retries a
truncated response once over TCP; encrypted transports never downgrade to
plaintext. AXFR and IXFR zone transfers are rejected because they require a
multi-message transfer protocol. `--resolver system` conflicts with direct-DNS
selectors instead of ignoring them.

Shell completion suggests record types accepted by the selected resolver:
`A`, `AAAA`, and `PTR` for the system resolver, the supported single-message
registry for direct DNS, and only `PTR` with `--reverse`. Names and server
addresses remain free-form and completion does not perform DNS discovery.

For PTR records, `--reverse` converts an IP address to its reverse owner name.
Without `--reverse`, direct mode sends the supplied owner name unchanged;
system mode accepts a literal IP address because `net.Resolver` does not expose
raw reverse-owner queries.

```fish
npc dns @192.0.2.53 example.com MX
npc dig @tcp://192.0.2.53 example.com TXT --short
npc dns @tls://resolver.example example.com AAAA --ca resolver-ca.pem
npc dns @https://resolver.example/dns-query example.com --ca resolver-ca.pem
npc nslookup example.com CAA --resolver dns --format json
```

DNS over TLS uses verified TLS with DNS-over-TCP framing. DNS over HTTPS sends
POST requests with `application/dns-message`, honors HTTPS proxy environment
variables, and limits responses to 65535 bytes. An HTTPS endpoint without a
path uses `/dns-query`; an explicit path and query are preserved. Redirects are
always errors and are never followed; any successful 2xx response is accepted.

Encrypted endpoints support `--ca`, `--system-ca`, `--servername`, `--cert`,
`--key`, and `--insecure`. These TLS options are rejected for plaintext UDP and
TCP endpoints. `--ca` replaces the system roots unless `--system-ca` is also
set. `--cert` and `--key` provide a client identity for mutual TLS.

When direct mode has no `@server`, npc uses configured nameservers from
`/etc/resolv.conf` on Unix and active network adapters on Windows. It does not
substitute a public resolver. Direct mode does not apply a resolver search list;
it canonicalizes the supplied name to a fully qualified DNS name. A received
DNS response, including NXDOMAIN or SERVFAIL, is rendered with its status and
counts as a completed exchange; transport, timeout, malformed-response, ID,
opcode, and question-mismatch failures exit nonzero.

`--short` prints one answer value per line. With `--format json`, it prints a
JSON array of values instead. TXT values retain DNS zone-file quoting and
escaping so embedded whitespace, quotes, control bytes, and multi-string TXT
records remain unambiguous. The `dig` and `nslookup` aliases accept exactly the
same syntax and flags as `dns`; they do not emulate those programs' `+option`
syntax.

DNS option validation, resolution, response validation, and rendering all
finish before npc opens `--output`. Those failures preserve an existing file.
The final result is then written through the normal output lifecycle; a write
or close failure after the file is opened can leave an empty or partial file,
and the nonzero exit status marks it incomplete.

### Checksums

Hash one stdin stream with an explicit algorithm. Text output defaults to
lowercase hexadecimal followed by a newline; `--encoding raw` writes the exact
digest bytes. MD5 and SHA-1 are available for compatibility checks.

```fish
printf 'hello' | npc hash sha256
npc hash sha512 --input archive.tar --output archive.tar.sha512
```

All hash algorithms accept `--input-encoding` and the shared output encodings.
They do not accept filename operands, labels, manifests, or multiple inputs.

### Raw TCP, TLS, and UDP walkthrough

`net connect` sends stdin or `--input` to an endpoint and copies the peer's
response to stdout or `--output`. At input EOF, it keeps the connection's write
side open while draining the response; `--close-write` opts into a TCP
half-close for protocols that require EOF before responding. The TCP form is a
compact netcat-style exchange:

```fish
printf 'hello\n' | npc net connect tcp localhost:9000
```

The TLS form verifies the server certificate and endpoint hostname by default.
Use a private test CA without changing the system trust store:

```fish
printf 'hello\n' | npc net connect tls localhost:9443 \
    --ca ca.crt
```

Add a client identity for mutual TLS. The certificate and private key are
required together and must match:

```fish
printf 'hello\n' | npc net connect tls localhost:9443 \
    --ca ca.crt \
    --cert client.crt \
    --key client.key
```

`--ca` replaces the system roots. Add `--system-ca` to combine the supplied CA
bundle with them. `--servername` overrides both SNI and the certificate name
used for verification. `--insecure` disables certificate and hostname
verification and cannot be combined with trust flags; its warning is shown
with `--verbose` connection diagnostics.

By default, npc advertises no ALPN protocols. Use `--alpn http/1.1`, `--alpn
h2`, or another comma-separated protocol list when the endpoint requires
explicit negotiation. ALPN negotiation never changes the bytes npc sends:
selecting `h2` requires the input itself to contain valid HTTP/2 frames.
Completion suggests common TCP/TLS identifiers (`h2`, `http/1.1`, `dot`,
`mqtt`, `postgresql`, `imap`, `pop3`, and `acme-tls/1`) and continues
comma-separated lists without reordering or repeating a selected identifier.
Custom and empty ALPN values remain valid. QUIC-only identifiers and `h2c` are
not suggested, and a suggestion does not add application protocol framing.
With Fish, Cobra may display an additional candidate ending in `.` when a
single ALPN match must leave the argument open for a comma. That dotted entry
is a completion workaround; select the undotted protocol identifier.

`--timeout` bounds only TCP setup and the TLS handshake (10 seconds by
default); established streaming is not timed out. After input EOF, `--wait`
allows up to 5 seconds for the peer to finish its response before npc closes the
connection. Set `--wait 0` to drain until the peer closes, or choose a shorter
duration for a protocol that keeps connections open. With `--close-write`, npc
half-closes before starting that drain period. If a finite wait expires, the
command closes the connection and exits nonzero with a drain-timeout error.
Bytes already written to stdout or `--output` remain available, but are a
partial response and must not be treated as complete. The aliases `npc nc` and
`npc netcat` select the same `net` command tree.
Completion offers `0`, `1s`, `5s`, `10s`, and `30s` for existing `--timeout`
and `--wait` flags; other valid Go durations remain accepted. No command gains
a new timeout or wait control from these suggestions.

UDP preserves datagram boundaries instead of exposing a byte stream. The
decoded stdin or `--input` payload becomes exactly one datagram, including when
it is empty. `net connect udp` writes the first response datagram to stdout or
`--output`, then exits:

```fish
printf 'hello over UDP' | npc net connect udp 127.0.0.1:9000 --verbose
```

The entire decoded request is buffered before it is sent, so stdin must reach
EOF; pressing Enter alone does not send a datagram. End interactive input with
EOF (Ctrl-D on Unix), use a command such as `printf` that closes its output, or
redirect an empty input to send a zero-length datagram:

```fish
npc net connect udp 127.0.0.1:9000 </dev/null
```

For UDP, `--timeout` retains the 10-second setup default and covers address
resolution and socket setup. `--wait` allows up to 5 seconds for the one
response datagram; `--wait 0` waits indefinitely. UDP does not expose
`--close-write` because it has no stream write side to half-close. The connector
always expects one response: a non-replying service produces a timeout error,
while `--wait 0` waits indefinitely. There is no send-only mode.

The byte encodings also make it possible to send and receive a raw DNS packet
when testing packet bytes themselves. Replace the endpoint and packet with the
resolver and query you intend to test:

```fish
printf '%s\n' '1a2b01000001000000000000076578616d706c6503636f6d0000010001' |
    npc net connect udp 1.1.1.1:53 \
        --input-encoding hex \
        --encoding hex
```

The command decodes the hexadecimal request into one raw DNS datagram and
prints the raw response datagram as hexadecimal. It does not interpret DNS
records or retry a truncated response over TCP.

`net listen tcp` binds a port and optional host, accepts one connection,
relays bytes with the same input, output, encoding, half-close, and drain
controls as `net connect`, then exits. In one terminal:

```fish
printf 'hello from listener\n' | npc net listen tcp 9000 --close-write --verbose
```

Connect from another terminal:

```fish
printf 'hello from client\n' | npc net connect tcp 127.0.0.1:9000 --close-write
```

The listener waits indefinitely for its connection by default. Set a positive
`--timeout` to bound address resolution, binding, and accepting. Port `0` asks
the operating system to choose an available port; use `--verbose` to print the
bound address before the accept begins. Supply only a numeric port to listen on
all available local IPv4 (`0.0.0.0`) and IPv6 (`::`) addresses; the `:port`
form remains accepted. Supply an IP address or name to restrict the listener to
that host.

`net listen tls` adds a required server certificate chain and matching private
key. The client supplies SNI; the listener reports it with `--verbose` but does
not configure it with a flag:

```fish
printf 'hello from TLS listener\n' | npc net listen tls 9443 \
    --cert server.crt \
    --key server.key \
    --verbose
```

Supplying `--ca` enables mutual TLS and requires every client to present a
certificate chaining to that bundle. Add `--system-ca` to combine system roots
with the bundle:

```fish
printf 'authenticated response\n' | npc net listen tls 127.0.0.1:9443 \
    --cert server.crt \
    --key server.key \
    --ca client-ca.crt \
    --system-ca \
    --alpn npc-example
```

Without `--ca`, the listener does not request a client certificate. It
advertises no ALPN protocols unless `--alpn` is supplied. Listener TLS setup
must finish before any stdin payload is relayed; a positive `--timeout` covers
binding, accepting, and the handshake, while established relay draining remains
governed only by `--wait`.

`net listen udp` waits for one request datagram, writes it to stdout or
`--output`, sends the decoded stdin or `--input` payload back to that same peer
as one response datagram, then exits. Start a listener in one terminal:

```fish
printf 'pong' | npc net listen udp 9000 --verbose
```

Send one request and receive its response from another terminal:

```fish
printf 'ping' | npc net connect udp 127.0.0.1:9000
```

Like the TCP and TLS listeners, a bare numeric UDP port binds all available
local IPv4 and IPv6 addresses, `:port` remains accepted, and an explicit host
restricts the bind. Its `--timeout` defaults to `0` and, when positive, covers
binding and receipt of the first datagram. Reading the response payload from
stdin and sending it happen outside that setup timeout. The listener sends a
zero-length response when its decoded input is empty; it does not expose
stream-only `--wait` or `--close-write` controls. As with the connector, the
response is not sent until stdin reaches EOF; pressing Enter alone is not
enough. Use `npc net listen udp 9000 </dev/null` for an empty response.

`cert connect` and `cert inspect` remain inspection commands: they always report
certificate verification status, but a failed verification is not enforced.
Text, long, and JSON views include it in their structured output; PEM views
report it on stderr so stdout remains a clean certificate artifact. `net
connect tls` is the data-bearing client and therefore fails the handshake before
sending input when verification fails.

### HTTP requests

A URL alone makes a GET request and streams the response body. Use an explicit
method for requests with bodies; body flags never silently change the method:

```fish
npc http https://example.com
npc http -X GET https://example.com --output response.html
npc http -X POST https://example.com/api --json '{"name":"demo"}'
npc http -X POST https://example.com/api --json @payload.json
printf 'payload' | npc http -X PUT https://example.com/object
npc http -X PROPFIND https://example.com/files --stdin never
```

Use `--method METHOD` or `-X METHOD` to select the request method. Standard
methods appear in flag completion; custom method tokens are also accepted,
preserving their spelling.
A bare `npc http` shows help. URLs without a scheme default to HTTPS:
`npc http whoami.example.com` uses `https://whoami.example.com`. Use an explicit
`http://` URL for plain HTTP; failed HTTPS requests never retry as HTTP.

Choose one body source: `--input FILE` for raw file bytes, `--input -` for
stdin, `--data/-d STRING` for literal bytes, or `--json JSON|@FILE|@-` for a JSON
body with `Content-Type: application/json`. JSON convenience sets the content
type without parsing or rewriting the payload. `--input-encoding` decodes raw
and JSON body sources using the same encodings as other npc commands.

Repeated `--form name=value` fields produce a URL-encoded form. Add `--file
name=path` for multipart fields and streamed regular-file uploads:

```fish
npc http -X POST https://example.com/form --form name=demo --form tag=one --form tag=two
npc http -X POST https://example.com/upload --form name=demo --file attachment=report.txt
npc http -X GET https://example.com -H 'Accept: application/json'
```

`--header/-H` is repeatable; an explicit content type overrides the raw/JSON/form
default. Requests send `User-Agent: npc/<version>` by default (`npc/dev` when
build version information is unavailable or reports `(devel)`). Use
`-H 'User-Agent: custom/1.0'` to override it or `-H 'User-Agent:'` to suppress it.
Generated shell completion can continue an unquoted `Authorization:Bearer ` or
`Authorization:Basic ` prefix in the same argument. Cobra's generated shell
scripts cannot request completion while a quoted header argument is still open.
Completion scripts generated with `--no-descriptions` also omit the space after
the authorization scheme; type it manually before entering credentials.
Multipart content type and boundary, content length, and transfer
encoding are generated from the body and cannot be supplied as custom headers.
For a manually constructed multipart body, `Content-Type: multipart/form-data`
must include the boundary matching that body. `--file` generates both body and
boundary and therefore rejects a custom content type.
Conflicting body sources, invalid options, and input/upload/output path
collisions are rejected before opening the output. Multipart `--file` paths
must be regular files; stdin uploads use the raw-body interface.

With `--stdin auto` (the default), an explicit method other than GET/HEAD uses
non-terminal stdin when no body source was supplied. Terminal stdin is left
alone unless explicitly selected. GET shorthand never consumes stdin and
rejects body flags; explicit GET/HEAD require explicit input to send a body.
Use `--stdin never` to keep inherited script input untouched, or `--stdin always`
to select stdin regardless of terminal status. Non-terminal input can still
block waiting for a producer. Once stdin is selected, the request owns it and
may close it to interrupt an upload on cancellation or an early response.

HTTPS verifies certificates and hostnames by default and negotiates HTTP/1.1
or HTTP/2. The existing `--ca`, `--system-ca`, `--cert`, `--key`, `--servername`,
and `--insecure` controls apply. HTTP uses normal environment proxy settings.
`--timeout` defaults to 10 seconds for dialing and TLS handshaking;
`--request-timeout` optionally bounds the whole exchange, including upload and
response transfer, and defaults to `0` (disabled).

Use repeatable `--resolve HOST:PORT:ADDRESS[,ADDRESS]` rules to connect a URL's
exact host and port through specified numeric addresses without changing its
HTTP Host header or TLS identity:

```fish
npc http https://service.example \
    --resolve service.example:443:192.0.2.10
npc http https://service.example \
    --resolve 'service.example:443:[2001:db8::10],192.0.2.10'
```

ASCII host matching is case-insensitive (international names use their ASCII
Punycode form), later rules for the same host and port replace earlier rules,
and addresses are attempted in their listed order. IPv6 hosts and addresses
use brackets. Rules also apply to matching redirect destinations. Wildcard
hosts and curl's temporary or removal rule forms are not supported. Environment
proxies remain in effect; when a proxy resolves the origin, an origin
`--resolve` rule does not bypass it.

Redirects are followed by default, up to `--max-redirects 10`; `--follow=false`
returns the first response. Standard 301/302/303 redirects change non-GET/HEAD
methods to GET and drop the body; 307/308 retain the method and body. Literal,
regular-file, and multipart regular-file bodies can be replayed. A redirect
requiring replay of stdin or another non-replayable stream returns that
redirect's body and an error. Redirect-limit failures also preserve the last
response body. No application-level retry loop is added.

HTTP 4xx/5xx statuses return nonzero while preserving the response body. Use
`--fail=false` to treat any completed HTTP response as success. Transport and
output failures still return errors. Partial output remains available under
npc's normal streaming-output contract.

By default, npc uses Go's HTTP transport to advertise `gzip` compression and
stream the decompressed response body. Automatic negotiation
is disabled for HEAD and range requests. Supplying `Accept-Encoding` yourself,
including an empty value, disables automatic negotiation and leaves the
response body and its encoding headers untouched.

By default, stdout or `--output` contains only the response body. HEAD prints
the status and headers; `--include` adds them for other methods. Body-only text
output also accepts `--encoding`; encoded output cannot be combined with
headers or a JSON envelope.

Tracing is an option on the request:

```fish
npc http -X GET https://example.com --trace
npc http -X GET https://example.com --format json --trace | jq .
```

Text-mode traces go to stderr and summarize each hop's DNS, connection, TLS,
first-byte, and transfer timings. `--format/-f json` instead emits a response
envelope containing method, final URL, status, protocol, headers, a `body`
string, `body_encoding: "base64"`, and `complete`. The body is always base64,
including JSON and text responses, and is streamed without buffering the whole
response. Bytes reflect the decoded HTTP response body when npc negotiated gzip
compression. URL passwords are redacted in reports.

With `-f json --trace`, the trace is embedded in the envelope rather than printed
on stderr. Failed transfers include an error and `complete: false` when the
output remains writable; a completed 4xx/5xx response has `complete: true` and
still returns nonzero by default. An output-write failure can leave incomplete
JSON. The JSON envelope already includes headers, so `--include` is rejected.

### gRPC discovery

`npc grpc HOST:PORT` lists services through server reflection. Select a service
or symbol for more focused discovery:

```fish
npc grpc api.example.com:443
npc grpc api.example.com:443 --list example.v1.EchoService
npc grpc api.example.com:443 --describe example.v1.EchoRequest
```

TLS certificate and hostname verification are enabled by default. The existing
`--ca`, `--system-ca`, `--servername`, `--cert`, `--key`, and `--insecure`
controls apply. Use `--plaintext` only for a cleartext HTTP/2 endpoint; it
conflicts with TLS controls. `--header/-H 'name: value'` is repeatable and is
sent to reflection. Metadata names ending in `-bin` accept standard Base64
values.

Reflection v1 is preferred. NPC falls back to the deprecated v1alpha protocol
only when v1 returns `Unimplemented`. `--protoset FILE` replaces reflection
with a protobuf `FileDescriptorSet`; service listing and schema description are
then offline and do not connect to `HOST:PORT`. Runtime `.proto` compilation is
not supported. Discovery output is text by default; `--format json` emits JSON
lists or a JSON descriptor. The official grpc-go transport and protobuf
packages are direct dependencies so wire behavior, reflection, dynamic schema
resolution, and descriptor formatting follow the maintained implementations.

One `--timeout` covers connection setup and reflection and defaults to 10
seconds; `0` disables the deadline. Descriptor data is limited to 16 MiB, 1,024
files, and 100 nested message levels. `--verbose/-v` writes status, response
metadata, and TLS details to stderr.

All local validation, descriptor resolution, and result serialization finish
before NPC opens `--output`. Opening an existing file is the truncation commit
point. A later write or close failure may leave partial output; NPC does not
provide atomic replacement, rollback, `fsync`, or durability guarantees.

### Key lifecycle walkthrough

Generate an Ed25519 private key in PKCS#8 PEM and its public half in canonical
PKIX PEM with one command, then inspect the private key's safe metadata without
printing private bytes:

```fish
npc key generate ed25519 \
    --output private.pem \
    --public-out public.pem
npc key inspect --input private.pem --format json
```

Inspect the public key separately. The private and public inspection results
have different `key_type` values but the same
`public_key_sha256_fingerprint`:

```fish
npc key inspect --input public.pem --format json
```

`--public-format` selects `pkix-pem` (the default), `pkix-der`, or `openssh`.
It applies only to `--public-out`; `--encoding` and `--mode` continue to apply
only to the private `--output`. The private key may go to stdout while the
public key goes to a file, but `--public-out -` is rejected because one stdout
stream cannot safely carry both artifacts. Use `key public` later when you need
to derive a public key from existing private material.

That fingerprint is calculated over canonical PKIX DER, so it is stable across
key containers. `cert inspect --format json` reports the same field, making it
possible to confirm that a certificate contains the expected public key:

```fish
npc cert inspect --input certificate.pem --format json
npc cert match --cert certificate.pem --key private.pem --format json
```

`cert verify` validates a leaf-first chain using system roots by default.
`--ca` replaces system roots, while `--ca ... --system-ca` combines them;
additional chain certificates and `--intermediates` remain untrusted chain
material. Use `--purpose`, `--hostname`, and `--at` to select the verification
policy. NPC does not fetch issuers, OCSP responses, or CRLs, although native
platform verification may have platform-dependent network behavior.

`cert match` compares the canonical public keys in any two or all three of a
certificate, key, and signed CSR. It does not check certificate trust, dates,
names, subjects, or CSR subject equality. Both commands emit text or JSON
reports; a failed verification or mismatch writes a completed report and exits
nonzero, while malformed input is rejected before an existing output is opened.

Derive the public key in the container needed by its consumer. `key public`
defaults to PKIX PEM and also supports PKIX DER and one canonical OpenSSH
`authorized_keys` entry:

```fish
npc key public --input private.pem --to openssh --output public.openssh
npc key public --input private.pem --to pkix-der --output public.der
npc key public --input private.pem --output public.pem
```

`key convert` reserializes a key while preserving whether it is private or
public. Public inputs can use `pkix-pem`, `pkix-der`, or `openssh`; private
inputs can use an algorithm-compatible PKCS#8, PKCS#1, or SEC1 target:

```fish
npc key convert --input public.pem --to pkix-der --output public.der
npc key convert --input private.pem --to pkcs8-der --output private.der
npc key inspect --input public.der
```

Earlier prerelease versions allowed `key convert` to derive public material
from private input. Replace those invocations with `key public --to`; rejected
private-to-public conversions report that command directly.

Binary key containers can be wrapped for text-only transport and decoded by any
key-consuming command. Encoding is not encryption; a base64-wrapped private key
must be protected exactly like the original:

```fish
npc key convert --input private.pem --to pkcs8-der \
    --encoding base64 --output private.der.b64
npc key inspect --input private.der.b64 \
    --input-encoding base64 --format json
```

Generation supports `ed25519`, `p256`, `p384`, `rsa2048`, `rsa4096`, and raw
`aes128|aes192|aes256` keys as a required argument. These compact names are
preferred; the descriptive aliases `ecdsa-p256`, `ecdsa-p384`, `rsa-2048`,
`rsa-4096`, and `aes-128|aes-192|aes-256` are also accepted.
Asymmetric private keys use PKCS#8 PEM; AES keys are raw bytes. PKCS#1 output is
limited to RSA private keys, SEC1 to ECDSA private keys, and PKCS#8 to supported
private-key algorithms. PKIX and OpenSSH targets contain only public material.

`key generate` treats regular output files as sensitive. A new destination is
created owner-only. Without an explicit Unix
`--mode`, an existing destination must be owned by the effective user and grant
no group or other permissions. macOS additionally suppresses inherited ACLs on
creation and rejects any extended ACL on an existing file. On Windows, the
current user must own the file and be the only principal granted access by a
protected DACL. An insecure destination is rejected before truncation,
preserving its contents and permissions. On Unix, an explicit `--mode` is a
deliberate override of that check; Windows continues to reject `--mode`.
Completion describes the existing encoding and format choices. For `--mode`,
it suggests `0600` (owner read/write), `0640` (also group-readable), and `0644`
(also world-readable); selecting a mode explicitly overrides the default,
preserved, or sensitive-output permissions. Other valid octal modes remain
accepted. Explicit boolean values such as `--follow=` complete `true` or
`false`, while bare flags such as `--follow` retain their usual behavior.
Stdout, FIFOs, and device outputs remain explicit streaming sinks and are not
permission-checked by npc.

`--public-out` follows the ordinary output-file contract: an existing file is
overwritten while retaining its permissions. npc validates that the private
and public paths are not direct, symlink, or hardlink aliases before opening
either output. The private key is written first; if the public write fails, the
private key is retained and the error identifies its path (or notes that it was
already emitted to stdout).

`key public`, `key inspect`, and `key convert` accept one unencrypted PKCS#8,
PKCS#1, or SEC1 private key, or one PKIX public key, in PEM or DER form. They
also accept one unencrypted OpenSSH private key or one `authorized_keys` public
entry for Ed25519, RSA, or ECDSA P-256/P-384/P-521. Blank lines, comment lines,
public-key options, and inline comments are accepted; extra key entries and
malformed non-comment lines are rejected. Options/comments are not retained
when canonicalizing a public key. Encrypted private keys are rejected without
prompting.

All three commands support `--input-encoding` for wrapped key bytes. `key
public` and `key convert` parse, validate, and serialize their complete result
before opening `--output`, so invalid input and incompatible conversions leave
existing destinations unchanged and do not create missing destinations.
Existing OpenSSH private keys also work with certificate creation and TLS
client/server identity loading. OpenSSH remains a public-key-only output
format; private-key generation and conversion keep their existing containers.

```fish
npc key inspect --input ~/.ssh/id_ed25519 --format json
npc key public --input ~/.ssh/id_ed25519 --to openssh --output id_ed25519.pub
npc key convert --input ~/.ssh/id_ed25519.pub --to pkix-der --output public.der
```

These examples require an unencrypted private key; passphrase-protected SSH
keys return the encrypted-private-key error.

The key noun and lifecycle verbs also have composable Cobra aliases for
interactive use:

```fish
npc k g ed25519                            # npc key generate ed25519
npc k p --input private.pem --to openssh   # npc key public
npc k i --input private.pem                # npc key inspect
npc k c --input private.pem --to pkcs8-der # npc key convert
```

The longer verb aliases are `gen`, `pub`, `ins`, and `conv`.

Shell completion describes key algorithms and output containers. Selecting
`--public-out` or `--public-format` limits algorithm suggestions to asymmetric
keys; selecting an AES algorithm omits the public-output options. Key material
and output paths are never inspected to infer compatible formats.

### Certificate creation walkthrough

Create a private key and a self-signed test CA. Certificate commands consume
private keys but never generate them, so key algorithm and output handling stay
under the `key generate` contract.

```fish
npc key generate ed25519 --output ca.key
npc cert create \
    --ca \
    --subject "CN=test-ca" \
    --key ca.key \
    --output ca.crt
```

Use that CA to mint separate server and client identities. Leaf certificates
default to 30 days and support both server and client authentication unless
`--server-only` or `--client-only` narrows them. CA certificates default to 365
days and cannot create subordinate CAs. An issued leaf starts no earlier than
its issuer and must use a short enough `--days` value to expire no later than its
issuer.

```fish
npc key generate ed25519 --output server.key
npc cert create \
    --dns localhost \
    --ip 127.0.0.1 \
    --server-only \
    --key server.key \
    --issuer-cert ca.crt \
    --issuer-key ca.key \
    --output server.crt

npc key generate ed25519 --output client.key
npc cert create \
    --subject "CN=client" \
    --client-only \
    --key client.key \
    --issuer-cert ca.crt \
    --issuer-key ca.key \
    --output client.crt
```

Inspect the resulting certificates using the normal certificate formatter:

```fish
npc cert inspect --input ca.crt --format long
npc cert inspect --input server.crt --format json
npc cert inspect --input client.crt
```

Use the same generation flags for certificate keys as for any other raw
keypair. Existing private keys may also be read from stdin by using `--key -`;
only one key or issuer flag can own stdin in a single invocation.

```fish
npc key generate p256 --output alternate-server.key
npc cert create \
    --dns localhost \
    --key alternate-server.key \
    --issuer-cert ca.crt \
    --issuer-key ca.key \
    --output alternate-server.crt
```

Create a minimal PKCS#10 request when a real CA owns certificate issuance:

```fish
npc cert csr \
    --subject "CN=service.internal" \
    --dns service.internal \
    --key alternate-server.key \
    --output service.csr
```

Issue a leaf directly from that request without access to its private key:

```fish
npc cert create \
    --csr service.csr \
    --issuer-cert ca.crt \
    --issuer-key ca.key \
    --output service.crt
```

CSR issuance verifies the request signature and preserves its complete subject
and DNS/IP SANs by default. `--subject`, `--dns`, and `--ip` replace only the
specified identity category. It accepts one strict PEM or DER request and
rejects unsupported requested extensions and SAN forms.

`--subject` currently accepts one `CN=<value>` component. DNS and IP values are
written as SAN extensions, not only into the common name. An issuer certificate
must be one PEM `CERTIFICATE`, its private key must match, and the requested
leaf validity must fit entirely within the issuer's validity window.
Shell completion offers the `CN=` subject prefix, common validity periods, and
stdin or filesystem choices for certificate key and issuer artifacts.
For direct certificate creation, server-capable leaves with no SAN flags
classify their common name as a matching DNS or IP SAN. With no subject or SAN
flags, directly created server-capable leaves and generated CSRs default to both
`CN=localhost` and a `localhost` DNS SAN; directly created client-only leaves
default to the same common name without a SAN. CSR issuance preserves the
request's identity without adding these defaults unless an identity category is
explicitly overridden.

These certificates and CAs are for test and development loops. npc never
installs trust roots; trust `ca.crt` only in an explicitly selected test store,
never system-wide. Direct `cert create` and `cert csr` generation require an
existing private key via `--key`; generate it separately with `key generate`.
`cert create --csr` instead uses the requester's public key from the CSR and the
issuer private key supplied by `--issuer-key`.

### AES quick start

Generate a new 256-bit key. `--output` writes the raw key bytes to `aes.key`, so
keep this file secret.

```fish
npc key generate aes256 --output aes.key
```

Encrypt a file with the default authenticated AES-GCM mode:

```fish
npc aes encrypt \
    --keyfile aes.key \
    --input document.txt \
    --output document.txt.gcm
```

Decrypt it using the same key:

```fish
npc aes decrypt \
    --keyfile aes.key \
    --input document.txt.gcm \
    --output recovered.txt
```

Prefer a new output path when decrypting. Runtime failures can leave an existing
`--output` file empty or partial.

For a small value or pipeline, encode the key and ciphertext as base64 so they
are safe to pass as text:

```fish
set key (npc key generate aes256 --encoding base64 | string trim)
set ciphertext (npc aes encrypt "secret message" --key "$key" --encoding base64)

npc aes decrypt "$ciphertext" --key "$key" --input-encoding base64
```

If the ciphertext needs to be bound to context, use the same `--aad` value when
encrypting and decrypting:

```fish
npc aes encrypt --keyfile aes.key --aad "customer=42;format=v1" \
    --input document.txt --output document.txt.gcm
npc aes decrypt --keyfile aes.key --aad "customer=42;format=v1" \
    --input document.txt.gcm --output recovered.txt
```

`aes encrypt` and `aes decrypt` default to authenticated AES-GCM. Its wire
format is `[12-byte random nonce][ciphertext][16-byte authentication tag]`.
GCM accepts `--aad`; the exact string bytes are authenticated but are not
stored in the ciphertext, so decryption requires the same value. Nonces are
generated internally and cannot be supplied by the caller. GCM reads one
message of at most 64 MiB before writing because authentication must complete
before any plaintext is released.

Use `--cipher-mode cbc` only for compatibility. CBC retains its existing wire
format, `[16-byte IV][PKCS#7-padded CBC ciphertext]`, and streams input and
output. `aes encrypt --cipher-mode cbc` generates a random IV when `--iv` is
omitted; `--iv` is not valid for GCM, and `--aad` is not valid for CBC. CBC is
unauthenticated: it cannot reliably detect tampering, a wrong key, or a wrong
mode, and successful decryption does not prove authenticity.

A single GCM key must encrypt no more than 2^32 messages in total across all
processes and machines that share it. Rotate well before that limit.

Binary input and output use `--input-encoding` and `--encoding/-e` with
`raw`, `hex`, `base64` (or the compatibility alias `b64`), `base64url`, or
`base32`. Structured certificate output uses `--format/-f`. This replaces the
old binary `--format/-f` axis and structured `--output-format/-F` axis; for
example, `cert connect -f hex` must be replaced with an applicable structured
format rather than a byte encoding.

Generate AES keys through `key generate aes128|aes192|aes256`; bare `key
generate` reports the required algorithm.

`x509`, `certificate`, and `x.509` are ordinary aliases for `cert`:
`npc x509 inspect` is equivalent to `npc cert inspect`. Bare aliases show help
immediately without reading stdin or emitting warnings. Existing invocations
that used a bare alias for inspection must add `inspect`.

For `--output` paths, npc opens the destination and streams output to it as the
command runs, following symlinks like normal shell redirection. Before opening
the output, npc validates encodings, AES mode-specific flags, key algorithm and
conversion-target values, and `--mode`, rejects directories and same-file
input/output pairs, inspects existing target types, and opens a named input
first. Errors after the output is opened can therefore leave an empty or partial
destination; the command's non-zero exit status indicates that the output is
incomplete.

The GCM crypter itself makes zero writer calls until encryption or authenticated
decryption succeeds. That does not preserve a CLI output file on runtime
failure: npc opens and truncates regular `--output` destinations before the
crypter runs, and encoders and operating-system writes have their own buffering
and failure behavior. Flag and mode validation occurs before that open.

A newly created regular destination requests mode `0600` on Unix; a restrictive
umask may remove additional owner permissions. Ordinary commands preserve an
existing file's permissions. Sensitive key-generating commands instead require
an existing regular destination to be owner-only, as described above, and
reject it before truncation otherwise. `--mode` (an octal permission string such
as `0640` or `640`) sets regular-file permissions explicitly on create or
overwrite, bypasses the sensitive-output check, and is applied before the
command runs. It is rejected for non-regular destinations, since npc has
nothing there to chmod, and on Windows, where POSIX permission bits cannot be
applied exactly. Non-regular destinations such as `/dev/stdout`, `/dev/fd/N`,
and FIFOs stream directly as well.

## Signals and exit status

Ctrl-C (SIGINT), SIGTERM, and SIGHUP end a run gracefully; on Windows only
Ctrl-C is handled. Commands stop waiting on the network or on input, close what
they opened, and flush `--output`. npc then prints `npc: interrupted` or
`npc: terminated` and exits with 128 plus the signal number: 130 for Ctrl-C,
143 for SIGTERM, and 129 for SIGHUP. Opening a FIFO for `--input` or `--output`
stops on the signal too. A run that has not finished 5 seconds after the first
signal, such as one blocked reading a key file from a FIFO, is ended anyway with
the same status and, when stderr accepts it, a `forced exit` note. Sending a
signal again ends a stuck run at once, unless npc inherited that signal as
ignored (SIGINT in a background job of a non-interactive shell, for example).

While a pager is showing a guide, Ctrl-C belongs to the pager: repeating it does
not end npc, and the 5-second limit is paused until the pager ends, then starts
over. SIGTERM and SIGHUP still end npc and its pager, even after a Ctrl-C.

Reading stdin or `--input` stops as soon as the signal arrives, even when no
more input is coming. SIGPIPE keeps its default behavior, so `npc ... | head`
ends when the reader closes, and SIGQUIT still dumps goroutines.

`--output` is opened and truncated before the command runs, so an interrupted
run can leave a partial file. Write to a temporary path and move it into place
when a partial result would be a problem.

## Development

Work is organized in two tiers:

- **Issues** track convergent work on what exists — correctness debt,
  consistency machinery, and the core capability build-out (keys, GCM,
  cert creation).
- **Milestones** capture the expansion arcs (mTLS, L4 transport, HTTP
  analysis, byte utilities, gRPC), each of which will decompose into
  multiple sub-issues when its predecessor work settles.

Tooling is managed by [mise](https://mise.jdx.dev): `mise install` provisions
the pinned toolchain, `mise tasks` lists every task, and `mise run
install:hooks` installs the pre-commit hooks. CI runs the same tasks against
the same pins. Task names follow verb:noun; a bare verb implies "all"
(`bench` runs every benchmark, `bench:cpu` narrows).

```sh
mise run build:dev      # development binary
mise run test:unit      # unit tests
mise run test:race      # race detector
mise run test:cover     # coverage + HTML report
mise run lint:go        # golangci-lint suite
mise run check          # lint and unit tests
mise run bench          # benchmarks
mise run scan:vuln      # govulncheck scan
```

Testing policy lives in [TESTING.md](TESTING.md) — the short version: every
fix ships with a regression test, coverage is maintained or increased by
every change, cryptographic code gets adversarial-input tests up front, and
unbounded-input code proves bounded memory in benchmarks. Curated command
guides follow the [help guide authoring standard](docs/help-authoring.md).

## Product direction and roadmap

This section preserves the intended product shape and design principles. It is
not a command reference: `grpc`, `sign`, `encode`, `decode`, `rand`,
`zip`, and `unzip` are future work. HTTP requests and TCP/TLS/UDP transport are
implemented. See
[Commands today](#commands-today) for the implemented surface.

### Product shape

npc is organized as **composable layers**, loosely following the OSI model.
Each layer's commands are useful alone, and each higher layer exposes rich
detail from the layers beneath it rather than reimplementing them:

| Layer | Domain                           | Nouns                                      |
| ----- | -------------------------------- | ------------------------------------------ |
| L4    | Raw transport (netcat successor) | `net` (`tcp`, `tls`, `udp`)                |
| L5/6  | TLS, X.509, crypto primitives    | `cert`, `key`, `aes`, `hash`, `sign`       |
| L7    | Application protocols            | `http`, later `grpc`                       |
| —     | Byte-level utilities             | `encode`, `decode`, `rand`, `zip`, `unzip` |

The layering is the identity of the tool, not a grab-bag: `http` output
surfaces TLS handshake and certificate detail via the `cert` machinery; `cert
connect` rides the same dialer as `tcp connect`; everything emits through the
same encoding/format pipeline. **A feature that cannot reuse the layer beneath
it is a signal it may not belong.**

### Positioning: wire, not artifacts

The differentiator is breadth plus layered inspection of **live connections**,
bound together by a shared command language.

- [smallstep's `step`](https://smallstep.com/docs/step-cli/) owns the
  certificate-_artifact_ lifecycle (create, inspect, verify, bundle, CA
  workflows) and does it well. npc does not compete there: artifact features
  are built to the minimum needed to make npc's wire-inspection loops
  self-contained, borrowing step's UX decisions where they are good.
- [`age`](https://age-encryption.org) owns no-knobs file encryption. If npc
  grows recipient-based file encryption, it speaks the age format rather than
  inventing a container (see Open decisions).
- npc's territory is what those tools structurally lack: probing **and
  serving** TLS with client identity (mTLS from both ends), STARTTLS, raw L4,
  HTTP timing/analysis, everyday symmetric encryption, and byte utilities —
  composing across layers in one binary.

In short: step manages identity artifacts; age encrypts files for humans;
**npc inspects live wire behavior and does everyday crypto plumbing.**

### Design principles

These are product features, not style preferences. Regressions against them
are bugs, and where possible they are enforced by tests rather than review.

1. **Noun-verb grammar.** `npc <noun> <verb> [mechanism] [flags]`.
   Nouns are resources (`cert`, `key`, `net`, `http`); verbs are actions
   (`inspect`, `generate`, `connect`, `listen`). Bare nouns print help — no
   implicit verbs. Knowledge must transfer: a user who has run `cert inspect`
   should correctly guess `key inspect`. HTTP defaults to GET when given a URL
   and accepts custom methods through `--method` (`-X`); bare `http` still
   shows help.

   _When is an algorithm a noun?_ An algorithm appears in the command path
   when it is (a) established by out-of-band mutual agreement between the
   parties, and (b) not derivable from self-describing inputs. Negotiated
   parameters (TLS ciphersuite, ALPN, HTTP version) are rendered in output,
   never encoded in command structure; derivable parameters (the key type
   inside a PEM block) come from the artifact. Hence `aes encrypt`,
   `hash sha256`, and `net connect tcp` name the mechanism — while `sign` does
   not (PEM keys are self-describing) and `http`/`cert connect` report what
   was negotiated.

2. **Two output axes, named consistently.**
   - `--encoding` / `-e`: byte serialization — `raw`, `hex`, `base64`,
     `base64url`, `base32`. Applies to binary output (keys, ciphertext,
     digests). Input gets the symmetric `--input-encoding`.
   - `--format` / `-f`: structured presentation — `text`, `long`, `json`,
     `pem`. Applies to structured output (certs, key metadata, analyses).

   The same words mean the same thing on every command.

3. **Universal I/O contract.** Every command reads stdin/`--input`, writes
   data to stdout/`--output`, and diagnostics to stderr. Commands compose:
   `npc key generate ed25519 | npc key public | npc encode base64`.

4. **`--format json` everywhere** structured output exists, for `jq`.

5. **Secure by default.** Authenticated encryption (AES-GCM) by default,
   modern key types such as Ed25519, randomness only from
   `crypto/rand`, legacy modes behind explicit flags — never silently. A
   generated private-key file output is owner-only. Ordinary commands request
   `0600` for new Unix files and preserve permissions when overwriting; the
   primary output of key-generating commands rejects an existing regular
   destination that is not already owner-only. npc never modifies system trust
   stores.

6. **Mechanical consistency.** Uniformity is enforced by shared machinery —
   persistent I/O hooks, encoder/formatter registries that derive help text,
   validation errors, and shell completion from one table — and pinned by
   conformance tests that walk the command tree. Future commands cannot merge
   in violation without failing CI.

7. **Narrow, differentiated dependencies.** Not zero-dependency — a policy:
   - No runtime dependencies: single static binary, no cgo, nothing resolved
     at execution time.
   - stdlib and `golang.org/x/*` are free; treated as stdlib.
   - Curated third-party libraries are welcome when differentiated: a
     mainline, high-quality library used substantially earns its place
     (cobra today; colored output and gRPC reflection anticipated). What is
     banned is _undifferentiated sprawl_ — trivial, poorly maintained, or
     transitively heavy dependencies.
   - Cryptographic primitives specifically stay stdlib/x-crypto. npc never
     takes third-party implementations of crypto, and never hand-rolls
     primitives.

8. **Bounded memory and low allocation.** Streaming algorithms stream;
   authenticated algorithms buffer only when their security contract requires
   it. Buffer sizes and limits are benchmarked, not guessed. Performance claims
   require benchmark evidence (`mise run bench`, compared with `benchstat`)
   before they are made.

### Open decisions

Recorded here so they are decided deliberately, not by accident:

- **age-format interop.** If recipient-based file encryption enters scope,
  adopt `age-encryption.org/v1` via `filippo.io/age` instead of a bespoke
  container, and add stanza-level inspection age itself doesn't prioritize.
  Decide when the feature is scheduled. Passphrase-derived keys (KDF choice)
  ride with this decision.
- **HTTP expansion.** Basic requests use `http URL [-X METHOD]`, with standard
  method flag completion for discoverability and `--trace` for diagnostics.
  Higher-level header analysis and gRPC remain later work.
- **nectat disposition.** The L4 core absorbs the `nectat` prototype
  (preserving its flush → cancel → linger → close shutdown ordering); the
  standalone repo is then archived.

### Artifact input limits

Key inspection, conversion, public-key extraction, certificate creation, certificate
matching keys and CSRs, and TLS
identity loading accept asymmetric key artifacts up to 1 MiB. Certificate
inspection, verification, matching, issuer certificates, and TLS certificate/CA bundles accept up to
16 MiB per input. For commands that support `--input-encoding`, these limits apply after decoding,
including stdin; oversized artifacts fail without parsing truncated data.
AES `--keyfile` accepts at most 32 raw bytes; keys must still be exactly 16, 24,
or 32 bytes. Raw network payload streams are not subject to artifact limits. Existing
output files are still opened before artifact reads for streaming commands, so a
read failure can leave them truncated under the normal streaming-output contract.
Certificate verification and matching instead prepare their bounded reports
before opening output.
