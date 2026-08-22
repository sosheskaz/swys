# NIST CAVP AES-GCM vectors

These are informal correctness vectors only. Their inclusion and successful use do not constitute NIST validation or certification of this implementation.

- Source: NIST Cryptographic Algorithm Validation Program archive `gcmtestvectors.zip`
- URL: <https://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip>
- Retrieved: 2026-08-10
- Archive SHA-256: `f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023`
- Members: `gcmEncryptExtIV{128,192,256}.rsp` and `gcmDecrypt{128,192,256}.rsp`

Each member was filtered without changing field values or vector ordering. Only complete sections with `IVlen = 96` and `Taglen = 128` were retained. This leaves 375 vectors per file (2,250 total), matching the wire format supported by this package. The filtered-file SHA-256 checksums are:

```
9b044d2a7869d8866226721cbb2f36f5b2c4ce86d7903d3099e4d93fc48d8597  gcmDecrypt128.rsp
118feea173d8eabea1b3743bddb87019682d65d2a45d4f789592515cbe8d90a2  gcmDecrypt192.rsp
8a181a506af7533004d5d923123381cc6498413c3ef4762a48bc434e13146150  gcmDecrypt256.rsp
892d78b2b2a3dbf2cc53b15df43b32fa445d77af7f485971dde5d37790c0ed97  gcmEncryptExtIV128.rsp
d1b92a7481013b22ded7c0f6e23eeb8a77df827445da22810a6ce4d314b2c98d  gcmEncryptExtIV192.rsp
9791600bfbf487b82f5d533bb472eba603fd6f1b5e873f4259f6f8fa16125074  gcmEncryptExtIV256.rsp
```
