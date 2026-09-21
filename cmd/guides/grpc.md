# Discover a gRPC service

Put the endpoint first. With no selector, NPC lists services using server reflection.

```sh
npc grpc api.example.test:443
npc grpc api.example.test:443 --list example.v1.EchoService
npc grpc api.example.test:443 --describe example.v1.EchoRequest
```

The list and describe selectors are mutually exclusive. Reflection v1 is preferred and falls back to v1alpha only when the server reports Unimplemented.

## Use TLS or an offline protoset

TLS certificate and hostname verification are enabled by default. Use the CA, server-name, or client-certificate flags for private services. Use the plaintext flag only for an explicitly cleartext HTTP/2 endpoint; it conflicts with TLS controls.

The protoset flag replaces reflection. Service listing and description then use the supplied FileDescriptorSet without connecting to the endpoint.

```sh
npc grpc 127.0.0.1:1 --protoset service.protoset
```

## Understand limits

Descriptor processing is limited to 16 MiB total, 1,024 files, and 100 nested message levels. One overall timeout covers connection setup and reflection.

Verbose reflection diagnostics include response headers immediately. Reflection trailers are available only after a receive error ends the stream; a successful reflection response does not wait for the server to close the stream, so trailers are unavailable in that case.

NPC prepares and serializes the discovery result before opening an output file. Once the output is opened, a write or close failure may leave it empty or partial.

For all flags and defaults, use the generated reference:

```sh
npc grpc --help
```
