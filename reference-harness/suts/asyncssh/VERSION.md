# asyncssh SUT (stream B1)

- Version: AsyncSSH 2.17.0 (PyPI, pip install asyncssh==2.17.0 in python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54).
- Source of the Dockerfile/server code: adapted from vendor/agentic-protocol-state-learning/targets/asyncssh (Apache-2.0, teammate's repo); changes: user tester / correct-horse-battery, publickey via /etc/psm/authorized_keys (installed by suts/b1/run.sh from keys/id_rsa.pub), RSA host key, diffie-hellman-group14-sha256 / rsa-sha2-256 / aes128-ctr / hmac-sha2-256 all offered by library defaults.
- Image: `psm-b1-asyncssh:pinned` (sha256:df568efe689d...). Container `psm-b1-asyncssh`, 127.0.0.1:2302->22. Mapper container `psm-mapper-b1-asyncssh` on 8302.
- Start: `bash suts/b1/run.sh asyncssh 2302` on the box (checks free disk >= 8 GB). Verify: `.venv/bin/python suts/b1/verify.py 2302`.
- Notes: server.py with RSA-3072 host key, password + authorized_client_keys=/etc/psm/authorized_keys; process_factory prints ok. Banner AsyncSSH_2.17.0.
- Server KEXINIT (OpenSSH client -vvv, server proposal is the second KEX/hostkey/cipher/MAC lines): `results/v2/B1/kexinit_asyncssh.txt`.
