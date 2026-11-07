# erlang-otp SUT (stream B1)

- Version: Erlang/OTP 29.1.2 ssh 6.0.7 (docker.io/library/erlang:29.1.2.0-slim@sha256:2110a9edc88a9788c07069e78fab3662fc91477b7902433a8b8bad9c852b0d1b).
- Source of the Dockerfile/server code: adapted from vendor/agentic-protocol-state-learning/targets/erlang-otp (Apache-2.0, teammate's repo); changes: user tester / correct-horse-battery, publickey via /etc/psm/authorized_keys (installed by suts/b1/run.sh from keys/id_rsa.pub), RSA host key, diffie-hellman-group14-sha256 / rsa-sha2-256 / aes128-ctr / hmac-sha2-256 all offered by library defaults.
- Image: `psm-b1-erlang-otp:pinned` (sha256:a4a0263a5eda...). Container `psm-b1-erlang-otp`, 127.0.0.1:2303->22. Mapper container `psm-mapper-b1-erlang-otp` on 8303.
- Start: `bash suts/b1/run.sh erlang-otp 2303` on the box (checks free disk >= 8 GB). Verify: `.venv/bin/python suts/b1/verify.py 2303`.
- Notes: ssh:daemon with RSA-3072 host key in /tmp/ssh-host-keys, user_dir /etc/psm (authorized_keys), auth_methods publickey,password. Banner Erlang/6.0.7.
- Server KEXINIT (OpenSSH client -vvv, server proposal is the second KEX/hostkey/cipher/MAC lines): `results/v2/B1/kexinit_erlang-otp.txt`.
