# Discover and call a gRPC service

Put the endpoint first. With no selector, NPC lists services using server reflection.

## Discover the service

The endpoint must be reachable and expose gRPC reflection. Replace api.example.test:443 and the example.v1 symbols below with your endpoint and its schema.

```sh
npc grpc api.example.test:443
npc grpc api.example.test:443 --list example.v1.EchoService
npc grpc api.example.test:443 --describe example.v1.EchoRequest
```

The list, describe, and positional method selectors are mutually exclusive. Use the discovered service and method names for invocation.

## Invoke one unary method

Name the method as SERVICE/METHOD and provide one protobuf JSON request through stdin, an input file, or **--data**. The example assumes a unary Echo method whose request and response contain a text field; use fields from your service's request schema.

```sh
npc grpc api.example.test:443 example.v1.EchoService/Echo \
  -d '{"text":"hello"}'
```

To extract the response text, install jq and compose the same invocation:

```sh
npc grpc api.example.test:443 example.v1.EchoService/Echo -d '{"text":"hello"}' | jq -r '.text'
```

Responses are protobuf JSON followed by a newline by default. Use the format flag with text for protobuf text with dynamic type resolution, including Any; json selects the default JSON explicitly. Streaming methods can be discovered but are not supported for invocation.

Discovery defaults to text. Use the format flag with json for JSON lists or descriptors. The encoding flag transforms the complete stdout result, including its trailing newline. For example, base64 encoding applies to the whole protobuf JSON or text response. Verbose diagnostics remain on stderr outside the encoder.

## Use TLS or an offline protoset

TLS certificate and hostname verification are enabled by default. Use **--ca**, **--servername**, or **--cert** with **--key** for private services; those credential files must already exist. Use **--plaintext** only for an explicitly cleartext HTTP/2 endpoint; it conflicts with effective TLS options.

The protoset flag replaces reflection. Service listing and description then use the supplied FileDescriptorSet without connecting to the endpoint. Invoking a method still connects after NPC resolves the schema and validates the request.

With protoc installed and your service schema available as service.proto, build a descriptor set including imported schemas:

```sh
protoc --include_imports --descriptor_set_out=service.protoset service.proto
npc grpc 127.0.0.1:1 --protoset service.protoset
npc grpc 127.0.0.1:1 --protoset service.protoset --describe example.v1.EchoRequest
```

## Decode TLS credentials independently

--ca-encoding, --cert-encoding, and --key-encoding select independent outer decoding for --ca, --cert, and --key and default to raw. They decode credential bytes before parsing; request JSON and the whole-output --encoding remain separate. Explicit companion flags require their source and conflict with --plaintext.

With a local TLS gRPC service running and encoded credentials:

```sh
npc grpc localhost:9443 example.v1.EchoService/Echo -d '{"text":"hello"}' \
  --ca ca.pem.b64 --ca-encoding base64 --cert client.pem.hex --cert-encoding hex --key client-key.pem
```

An exact - selects original stdin for one credential; ./- names a file. Invocation owns non-terminal stdin implicitly, and --input - owns it explicitly. Use a literal --data request or an input file to release stdin for credentials. Implicit terminal input defaults to an empty object; discovery has no request stdin. Multiple stdin owners fail before reads or connections. Reflection completion stays quiet when any credential selects stdin.

The endpoint is still required syntactically for offline discovery; these protoset-only commands do not contact it. Completion can suggest message, enum, and declared nested types from the local set. Live reflection completion lists services and resolves descriptors only for a selected service prefix; it does not crawl every service to discover unrelated type names.

## Understand input, limits, and remote effects

Implicit terminal stdin and empty input mean an empty JSON object; use **--input -** to read a request explicitly from a terminal. **--data** and **--input** are mutually exclusive and require a method selector. NPC collects request input before connecting or starting the overall timeout. NPC's standard signal handling cancels input collection, including an opened FIFO, and later network work. Unknown fields and trailing JSON values are rejected before invocation.

Reflection v1 is preferred and falls back to v1alpha only when the server reports Unimplemented.

The RPC message limit applies to invoked request and response protobuf messages. Descriptor processing has separate limits: 16 MiB total, 1,024 files, and 100 nested message levels. After request input, including FIFO input, is collected, one overall --timeout (-t) covers connection setup, reflection, and invocation. It defaults to ten seconds; zero disables it. Use an external process timeout when input collection must share the same fixed deadline as network work.

Verbose reflection diagnostics include response headers immediately. Reflection trailers are available only after a receive error ends the stream; a successful reflection response does not wait for the server to close the stream, so trailers are unavailable in that case.

NPC disables service-config retries and adds no application retry loop. The gRPC library may transparently retry only when it can determine that the server did not process the RPC. After invocation begins, a timeout, lost response, cancellation, or local output failure does not prove the server did not execute the method; there is no exactly-once guarantee.

Unsupported output encodings and invalid --mode values are rejected before reading request input or contacting the server. The --mode flag requires a regular output file and cannot be used with --output -.

NPC prepares and serializes the result before opening an output file. Once the output is opened, a write or close failure may leave it empty or partial even though remote execution already occurred.

For all flags and defaults, use the generated reference:

```sh
npc grpc --help
```
