# Getting started with NPC

Use NPC to inspect network services, exchange bytes, and work with keys and certificates. Commands are organized by task, with predictable stdin, stdout, and file options where those operations make sense.

## Start with the task

- **dns** resolves names or asks a particular DNS server.
- **grpc** discovers services and invokes unary RPC methods.
- **http** makes an HTTP request and writes its response body.
- **net** sends or receives raw bytes over TCP, TLS, or UDP.
- **cert** inspects certificates or creates test identities.
- **key** inspects or converts cryptographic keys.
- **aes** generates keys and encrypts or decrypts messages.
- **hash** computes a digest of a file or stdin for comparison.

## Try an offline workflow

Create a key and a certificate for a local test service, then inspect their metadata without printing the private material.

```sh
npc cert keygen --output private.pem
npc key inspect --input private.pem
npc cert create --key private.pem --dns localhost --output localhost.pem
npc cert inspect --input localhost.pem
```

The certificate names the identity; the private key proves possession of it. Keep the key private. This self-signed certificate is for explicit local testing, not automatic trust by other clients.

## Follow the command hierarchy

Most families use a noun followed by an operation. Net connect and net listen use TCP by default; select UDP with --udp or TLS with --tls. DNS, gRPC, and HTTP accept their target directly.

Commands that process bytes commonly read stdin and write stdout. Use the input and output file flags where applicable; individual guides explain commands with different input behavior.

## Choose your next step

```sh
npc help net
npc help cert inspect
npc --help
```
