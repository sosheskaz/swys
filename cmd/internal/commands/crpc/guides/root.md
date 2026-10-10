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
HTTP/1.1 servers. Redirects are not followed and calls are not retried.

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
nonzero. Request validation and unary failures preserve existing output files.

## Limits and timeouts

-c/--connect-timeout allows 10 seconds for connection and TLS setup.
-t/--timeout bounds the entire RPC after request input has been collected;
its default is unlimited. A zero duration disables that timeout. Input
collection remains interruptible by signals, independently of network timeouts.

--max-message-size limits each uncompressed JSON message to 16 MiB by default.
It does not convert large integers to floating-point values or require a JSON
object: the server determines the request's protobuf JSON shape.

For the complete flag reference:

```sh
swys crpc --help
```
