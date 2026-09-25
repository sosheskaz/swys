# Derive or canonicalize a public key

Read a private key and emit its public component, or read an existing public key and emit a canonical public representation. This command never emits private material.

## Create a public key file

Start with an existing private.pem, or generate one as shown here. Both output forms below refer to the same key.

```sh
npc key generate ed25519 --output private.pem
npc key public --input private.pem --output public.pem
```

Create one OpenSSH authorized-keys entry from a supported key.

```sh
npc key public --input private.pem --to openssh --output id_ed25519.pub
```

## Request a certificate for that key

A certificate authority usually needs a signing request, not the bare public key. Create the request with the same private key so it includes proof of possession and the requested name.

```sh
npc cert csr --key private.pem --dns service.example.test --output service.csr
```

Share the public key or request for the intended task; keep private.pem local. NPC creates the request but does not submit it to an authority.

Use key convert when the output must retain the input's private or public identity instead of deriving public material.

## Reference

```sh
npc key public --help
npc help cert csr
```
