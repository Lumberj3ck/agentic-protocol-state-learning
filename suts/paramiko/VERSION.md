# paramiko SUT (stream B1)

- Version: paramiko 5.1.0 (PyPI, pip install paramiko==5.1.0 in python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54, arm64).
- Source of the Dockerfile/server code: adapted from vendor/agentic-protocol-state-learning/targets/paramiko (Apache-2.0, teammate's repo); changes: user tester / correct-horse-battery, publickey via /etc/psm/authorized_keys (installed by suts/b1/run.sh from keys/id_rsa.pub), RSA host key, diffie-hellman-group14-sha256 / rsa-sha2-256 / aes128-ctr / hmac-sha2-256 all offered by library defaults.
- Image: `psm-b1-paramiko:pinned` (sha256:912cfc4eac71...). Container `psm-b1-paramiko`, 127.0.0.1:2301->22. Mapper container `psm-mapper-b1-paramiko` on 8301.
- Start: `bash suts/b1/run.sh paramiko 2301` on the box (checks free disk >= 8 GB). Verify: `.venv/bin/python suts/b1/verify.py 2301`.
- Notes: Own server.py (ServerInterface, library defaults, strict KEX default on); RSA-3072 host key generated at start. Banner paramiko_5.1.0.
- Server KEXINIT (OpenSSH client -vvv, server proposal is the second KEX/hostkey/cipher/MAC lines): `results/v2/B1/kexinit_paramiko.txt`.
