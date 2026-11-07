# russh SUT (stream B1)

- Version: russh 0.65.1 (crates.io, features ring+rsa; Cargo.toml pins =0.65.1; rust:1.92.0-slim-bookworm@sha256:f1f73538ebe623fd3673a35aff3df358ae1084c64c55646516e5b17b321b6c9b; runtime debian:bookworm-slim@sha256:734a...).
- Source of the Dockerfile/server code: adapted from vendor/agentic-protocol-state-learning/targets/russh (Apache-2.0, teammate's repo); changes: user tester / correct-horse-battery, publickey via /etc/psm/authorized_keys (installed by suts/b1/run.sh from keys/id_rsa.pub), RSA host key, diffie-hellman-group14-sha256 / rsa-sha2-256 / aes128-ctr / hmac-sha2-256 all offered by library defaults.
- Image: `psm-b1-russh:pinned` (sha256:0747d9d1a336...). Container `psm-b1-russh`, 127.0.0.1:2305->22. Mapper container `psm-mapper-b1-russh` on 8305.
- Start: `bash suts/b1/run.sh russh 2305` on the box (checks free disk >= 8 GB). Verify: `.venv/bin/python suts/b1/verify.py 2305`.
- Notes: Teammate Cargo.lock does not cover the added `rsa` feature, so the build runs `cargo build` without --locked; the resolved lock file is kept in the image at /Cargo.lock.resolved. Host keys RSA (random) + Ed25519 generated at start. Publickey: auth_publickey_offered checks /etc/psm/authorized_keys, auth_publickey (after signature verification) re-checks. Banner russh_0.65.1.
- Server KEXINIT (OpenSSH client -vvv, server proposal is the second KEX/hostkey/cipher/MAC lines): `results/v2/B1/kexinit_russh.txt`.
