# libssh SUT (stream B1)

- Version: libssh 0.12.2 (https://www.libssh.org/files/0.12/libssh-0.12.2.tar.xz, sha256 49560f677d96e3706a904ac2de1116e25f3680937d51e5c92198fcba4a1c1e9f; debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc).
- Source of the Dockerfile/server code: adapted from vendor/agentic-protocol-state-learning/targets/libssh (Apache-2.0, teammate's repo); changes: user tester / correct-horse-battery, publickey via /etc/psm/authorized_keys (installed by suts/b1/run.sh from keys/id_rsa.pub), RSA host key, diffie-hellman-group14-sha256 / rsa-sha2-256 / aes128-ctr / hmac-sha2-256 all offered by library defaults.
- Image: `psm-b1-libssh:pinned` (sha256:52b3ad64d2536...). Container `psm-b1-libssh`, 127.0.0.1:2304->22. Mapper container `psm-mapper-b1-libssh` on 8304.
- Start: `bash suts/b1/run.sh libssh 2304` on the box (checks free disk >= 8 GB). Verify: `.venv/bin/python suts/b1/verify.py 2304`.
- Notes: Server API (ssh_bind/ssh_handle_key_exchange/ssh_event), server.c from teammate extended with auth_pubkey_function and a second host key (RSA-3072 PEM via openssl at build) next to Ed25519. Banner libssh_0.12.2.
- Server KEXINIT (OpenSSH client -vvv, server proposal is the second KEX/hostkey/cipher/MAC lines): `results/v2/B1/kexinit_libssh.txt`.
