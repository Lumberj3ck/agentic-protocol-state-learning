# wolfssh SUT (stream B1)

- Version: wolfSSH 1.6.0 (v1.6.0-stable, https://www.wolfssl.com/wolfssh-1.6.0.tar.gz sha256 5bd4425d40a451607c78fcab2629242751e6cc59b5c9ebdfa4805fc704e1bfef) + wolfSSL 5.9.4 (sha256 a6de5589c07c485cd72f520d9ac3872099e6d235bffc31058bc4c2d7f98bfe64); debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc.
- Source of the Dockerfile/server code: adapted from vendor/agentic-protocol-state-learning/targets/wolfssh (Apache-2.0, teammate's repo); changes: user tester / correct-horse-battery, publickey via /etc/psm/authorized_keys (installed by suts/b1/run.sh from keys/id_rsa.pub), RSA host key, diffie-hellman-group14-sha256 / rsa-sha2-256 / aes128-ctr / hmac-sha2-256 all offered by library defaults.
- Image: `psm-b1-wolfssh:pinned` (sha256:9e292fd8eec8...). Container `psm-b1-wolfssh`, 127.0.0.1:2307->22. Mapper container `psm-mapper-b1-wolfssh` on 8307.
- Start: `bash suts/b1/run.sh wolfssh 2307` on the box (checks free disk >= 8 GB). Verify: `.venv/bin/python suts/b1/verify.py 2307`.
- Notes: Fork-per-connection server.c from teammate, extended: tester/password and publickey blob match against /etc/psm/authorized_keys; RSA-3072 host key (PEM, generated at image build; rebuild rotates it). Banner wolfSSHv1.6.0. Note: one stock-paramiko password login failed once with "No existing session" (see results/v2/B1/).
- Server KEXINIT (OpenSSH client -vvv, server proposal is the second KEX/hostkey/cipher/MAC lines): `results/v2/B1/kexinit_wolfssh.txt`.
