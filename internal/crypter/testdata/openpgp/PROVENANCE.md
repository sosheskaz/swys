# BZip2 literal fixture

`literal-sha256-16k.bz2` is a BZip2 stream containing one binary OpenPGP
literal packet with an empty filename and zero date. Its 16384-byte plaintext
is the concatenation of SHA-256 digests of big-endian `uint32` values 0 through
511, which the Go tests regenerate. Go has no BZip2 encoder, so the fixture was
generated offline with Python 3.14.7's standard `bz2` module at block size 1:

```python
import bz2, hashlib, struct
data = b"".join(hashlib.sha256(struct.pack(">I", i)).digest() for i in range(512))
body = b"b" + b"\x00" + b"\x00\x00\x00\x00" + data
literal = b"\xcb\xff" + struct.pack(">I", len(body)) + body
open("literal-sha256-16k.bz2", "wb").write(bz2.compress(literal, 1))
```

The fixture is 16870 bytes, larger than one small AEAD chunk budget, so the
decoder must read its whole block before yielding the literal header. SHA-256 of
the fixture is `5445775beda448d222f3cc83e897c3e16d260abe47d7eae5a7ed3dc57a6d4e5d`.
