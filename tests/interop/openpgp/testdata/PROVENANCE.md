# Sequoia AES-256-GCM fixture

`sequoia-aes256-gcm.pgp` was generated with the test-only Rust helper in this directory, using `run.sh encrypt /scratch/key /scratch/plain /scratch/wire` in the pinned `rust:1.90.0@sha256:e227f20ec42af3ea9a3c9c1dd1b2012aa15f12279b5e9d5fb890ca1c2bb5726c` image and the checked-in `Cargo.lock` with `sequoia-openpgp = 2.4.1`. The raw AES-256 session key is 32 repetitions of byte `0x42`; the plaintext is bytes `00 4f 70 65 6e 50 47 50 0a ff`. These are public, artificial test values.

The helper's packet inspection reported `SEIP version=Some(2)`. Its decryption produced the original plaintext. SHA-256 of the fixture is `a4d7a285065e325c6aaa91854b3bdb8ae02c572c719493262f0433f7bf84140b`.

`sequoia-two-literals.pgp` uses the same public key and first literal, followed by a second literal containing `unexpected second literal` inside the authenticated SEIPDv2 packet. It was generated with `run.sh encrypt-two-literals /scratch/key /scratch/plain /scratch/wire-two-literals`; the helper rejects it on decrypt because it contains two literals. SHA-256 is `add9a95a02c93192053aa1944120f2781eeb790f21af522189bd2ce347f0f70c`.

`sequoia-text.pgp` was generated with `run.sh encrypt-text` and contains a Unicode-marked literal with exact plaintext `line one\r\nline two\n`. The helper decrypted it to those exact bytes. SHA-256 is `f1c78a6c0dd0370a0532e891cac9aa82e9f9c42cfe2496c23f6e083f1cfeb377`.

`sequoia-compressed.pgp` was generated with `run.sh encrypt-compressed` and contains a Zlib-compressed literal inside SEIPDv2. The helper decrypted it to the original binary plaintext. This uses Sequoia's `compression-deflate` feature alongside the pinned cryptographic features. SHA-256 is `2a95bcba58b8128dd4ebda7e2a619041170130f7e6445e21284f207f4d1322d9`.

`sequoia-password-argon2.pgp` was generated with `run.sh password-encrypt /scratch/password /scratch/plain /scratch/wire`. It contains an AES-256 GCM SKESK v6 with Argon2 S2K (2 passes, 4 lanes, 2^10 KiB) followed by SEIPDv2, because Sequoia's `Encryptor` defaults to iterated S2K. The password is the public, artificial ASCII string `npc synthetic fixture password`; the plaintext is the same bytes as `sequoia-aes256-gcm.pgp`. The helper's inspection reported `SKESK version=Some(6)` and `SEIP version=Some(2)`, and `run.sh password-decrypt` produced the original plaintext. SHA-256 is `0d74fb04e4a7893001b1b3a38db6b5687e651260677b5907baea9e633bae6fde`.
