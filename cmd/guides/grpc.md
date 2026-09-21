# Discover and call a gRPC service

Put the endpoint first. With no selector, NPC lists services using server reflection.

```sh
npc grpc api.example.test:443
npc grpc api.example.test:443 --list example.v1.EchoService
npc grpc api.example.test:443 --describe example.v1.EchoRequest
```

The list, describe, and positional method selectors are mutually exclusive. Reflection v1 is preferred and falls back to v1alpha only when the server reports Unimplemented.

## Invoke one unary method

Name the method as SERVICE/METHOD and provide one protobuf JSON request through stdin, an input file, or the data flag. Implicit terminal stdin and empty input mean an empty JSON object; use the input flag with - to read a request explicitly from a terminal. NPC collects request input before connecting or starting the overall timeout. NPC's standard signal handling cancels input collection, including an opened FIFO, and later network work. Unknown fields and trailing JSON values are rejected before invocation.

```sh
npc grpc api.example.test:443 example.v1.EchoService/Echo \
  -d '{"text":"hello"}'
```

Responses are protobuf JSON followed by a newline. Streaming methods can be discovered but are not supported for invocation.

## Use TLS or an offline protoset

TLS certificate and hostname verification are enabled by default. Use the CA, server-name, or client-certificate flags for private services. Use the plaintext flag only for an explicitly cleartext HTTP/2 endpoint; it conflicts with TLS controls.

The protoset flag replaces reflection. Service listing and description then use the supplied FileDescriptorSet without connecting to the endpoint. Invoking a method still connects after NPC resolves the schema and validates the request.

```sh
npc grpc 127.0.0.1:1 --protoset service.protoset
```

## Understand limits and remote effects

The RPC message limit applies to invoked request and response protobuf messages. Descriptor processing has separate limits: 16 MiB total, 1,024 files, and 100 nested message levels. After request input, including FIFO input, is collected, one overall timeout covers connection setup, reflection, and invocation. Use an external process timeout when input collection must share the same fixed deadline as network work.

Verbose reflection diagnostics include response headers immediately. Reflection trailers are available only after a receive error ends the stream; a successful reflection response does not wait for the server to close the stream, so trailers are unavailable in that case.

NPC disables service-config retries and adds no application retry loop. The gRPC library may transparently retry only when it can determine that the server did not process the RPC. After invocation begins, a timeout, lost response, cancellation, or local output failure does not prove the server did not execute the method; there is no exactly-once guarantee.

NPC prepares and serializes the result before opening an output file. Once the output is opened, a write or close failure may leave it empty or partial even though remote execution already occurred.

For all flags and defaults, use the generated reference:

```sh
npc grpc --help
```
