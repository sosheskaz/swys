# Connect RPC

Call a Connect RPC service with JSON. connectrpc is an alias for crpc.
Ordinary requests do not require reflection or a protobuf schema.

## Basic usage

```sh
swys crpc https://api.example.com/example.v1.EchoService/Echo -d '{"text":"hello"}'
swys crpc https://api.example.com example.v1.EchoService/Echo -d '{"text":"hello"}'
```

Schemeless addresses use HTTPS. Use http:// explicitly for cleartext local
services. HTTPS negotiates HTTP/2 when available; unary calls also work with
HTTP/1.1 servers. Server and client streaming also support HTTP/1.1. Redirects are not followed and calls are not retried.

## Work with files and pipelines

```sh
swys crpc localhost:8443/example.v1.EchoService/Echo --ca local-ca.pem -i request.json -o response.json
printf '%s' '{"text":"hello"}' | swys crpc http://localhost:8080/example.v1.EchoService/Echo
swys crpc api.example.com/example.v1.EchoService/Echo -d '{"text":"hello"}' | jq -r .text
```

-d/--data takes one JSON value. Otherwise the command reads piped stdin, or
uses {} when no input is available. -i/--input - explicitly reads stdin,
including a terminal; --stdin never sends {} without reading stdin. Empty
explicit data or files are invalid JSON. --input-encoding decodes request
bytes; -e/--encoding independently encodes the JSON response.

## Stream messages

Use --stream server for one request and many responses, --stream client for
many requests and one response, or --stream bidi for both. Without --stream,
the command makes a unary call. These examples require services offering the
named streaming methods:

```sh
swys crpc api.example.com/example.v1.Events/Watch --stream server -d '{"topic":"deployments"}'
swys crpc http://localhost:8080/example.v1.Events/Upload --stream client -i events.jsonl -o summary.json
swys crpc api.example.com/example.v1.Chat/Exchange --stream bidi -i requests.jsonl | jq --unbuffered -r .text
```

Multiple-message input and output use JSON Lines: one complete JSON value per
line. Blank input lines are ignored, CRLF is accepted, and the last message
need not end with a newline. -d supplies exactly one message even when its
JSON spans lines. An empty client or bidi input sends zero messages.

Bidirectional streaming requires HTTP/2. HTTPS negotiates it; explicit http://
uses cleartext HTTP/2 automatically for bidi calls. Other cleartext calls use
HTTP/1.1. Sending finishes at input EOF while responses continue. The server's
final status ends the call even if input remains open. Responses already
written by a server or bidi stream remain on stdout if a later message or
final status fails; stderr and the exit status report the error. Client streams
write their single response only after successful final status.

## Discover a schema

A bare origin lists services. Add --list SERVICE to list its methods, or
--describe SYMBOL to inspect a protobuf descriptor. A literal trailing slash
marks a routed base URL. Explicit discovery flags always treat the URL as a base.

```sh
swys crpc api.example.com
swys crpc https://api.example.com/rpc/ --list example.v1.EchoService
swys crpc api.example.com --describe example.v1.Request --format json -o request-type.json
swys crpc --protoset api.protoset --list example.v1.EchoService
```

--protoset loads a binary FileDescriptorSet, including imports, without
reflection. Offline discovery needs no URL. Discovery defaults to text;
--format plain uses the same undecorated list/protobuf layout, and --format
json emits a JSON list or protobuf descriptor.

Use --reflect to obtain the selected method's schema before calling it, or
--protoset to use a local schema. Both validate the request's protobuf JSON
shape and infer unary/server/client/bidi cardinality. An explicitly conflicting
--stream is an error; explicit schema failures never fall back to schema-free
invocation. Ordinary calls without these flags still need no schema.

```sh
swys crpc api.example.com example.v1.EchoService/Echo --reflect -d '{"text":"hello"}'
swys crpc http://localhost:8080/example.v1.Events/Watch --protoset api.protoset -d '{"topic":"deployments"}'
```

Reflection requires HTTP/2, using cleartext HTTP/2 for http://. It supports
standard gRPC reflection v1, falling back to v1alpha only when v1 reports
Unimplemented. It fetches the requested symbol and imports, not every service.
--reflection-timeout defaults to 10 seconds for the whole lookup, including
stream completion; it is separate from the invocation timeout. Schemas have
independent limits of 16 MiB of descriptors, 1,024 files, and 100 nested message
levels. --max-message-size controls RPC payloads only.

## Build a request from the schema

--template SERVICE/METHOD prints editable protobuf JSON without calling the
method. Use reflection, or provide a local protoset for offline work:

```sh
swys crpc api.example.com --template example.v1.EchoService/Echo -o request.json
swys crpc --protoset api.protoset --template example.v1.EchoService/Echo -o request.json
swys crpc api.example.com example.v1.EchoService/Echo --reflect -i request.json -o response.json
```

Edit request.json before sending it. Templates show field defaults, empty
lists/maps, and nested objects. They leave oneof choices unselected and do not
invent IDs or other business values. Recursive references and messages beyond
four object levels remain null. Expansion is bounded to 4,096 fields; a template
is a starting point, not a promise that the service accepts those values.
--format jsonl puts the template on one line for a streaming request file.

With shell completion installed, use the base-URL-plus-method form and press
Tab after the service prefix, then after SERVICE/ to see methods with request,
response, and streaming descriptions. --list, --describe, and --template also
complete schema symbols. See swys help completion for shell setup.

Completion uses --protoset when supplied; otherwise it queries reflection with
a hard two-second cap and honors shorter connection/reflection timeouts. It
reuses TLS, header, and address-override flags, but never invokes application
methods, reads stdin or FIFOs, or writes output files. Unavailable reflection
returns no suggestions. It does not crawl all service schemas or persist them.

## Authentication and diagnostics

```sh
swys crpc api.example.com/example.v1.EchoService/Echo -H 'Authorization: Bearer TOKEN' -d '{}' -v
swys crpc api.example.com/example.v1.EchoService/Echo --cert client.pem -k client.key -d '{}'
swys crpc api.example.com/example.v1.EchoService/Echo --resolve api.example.com:443:127.0.0.1 -d '{}'
```

Custom CAs replace system roots unless --system-ca is supplied. TLS artifacts
have independent --ca-encoding, --cert-encoding, and --key-encoding flags;
only one payload or artifact can own stdin. --resolve changes the connection
address while preserving the URL's host and TLS identity. Standard HTTP proxy
environment variables apply.

The response JSON goes to stdout. -v/--verbose writes RPC status, response
metadata, and transport details to stderr. RPC and protocol failures exit
nonzero. Request validation and unary failures preserve existing output files. Streaming outputs are written incrementally.

## Limits and timeouts

-c/--connect-timeout allows 10 seconds for connection and TLS setup.
-t/--timeout bounds the entire RPC after request input has been collected;
its default is unlimited. For client and bidi streams, it includes pauses
between input messages. -w/--wait bounds the entire response drain after
sending finishes, including waiting for response headers. It does not reset
for incoming messages and also defaults to unlimited. A zero duration
disables a timeout; the earliest applicable
deadline wins. Single-request input collection remains interruptible by
signals, independently of network timeouts.

--max-message-size limits each uncompressed JSON message to 16 MiB by default.
It does not convert large integers to floating-point values or require a JSON
object: the server determines the request's protobuf JSON shape.

For the complete flag reference:

```sh
swys crpc --help
```
