# libssh server target

Uses the C server API from the official libssh 0.12.2 release:
https://www.libssh.org/files/0.12/libssh-0.12.2.tar.xz
The Dockerfile verifies the release archive's SHA-256 checksum and builds a
stripped shared library in a separate build stage. The runtime contains only
the server, libssh, OpenSSL and the Debian base dependencies.

The server generates an Ed25519 host key at startup, listens on container port
22, and uses libssh's default algorithm lists (including curve25519-sha256,
aes128-ctr, hmac-sha2-256 and strict KEX). Compression is disabled at build time,
so it offers none. No system SSH configuration is loaded.

Only password authentication for test/test succeeds. Each connection has its
own thread and accepts session channels after authentication. An exec request
for any command succeeds and returns exit status 0, EOF and channel close;
the command is not executed. Incoming channel data is consumed and discarded.
Transport parsing, key exchange, rekey, authentication message handling and
channel framing are provided by libssh without protocol patches.

Validation:

```sh
SMLEARN_TARGETS=libssh uv run pytest -q tests/test_ssh_mapper.py
```

If the local Docker client configuration directory is read-only, point
DOCKER_CONFIG at a writable temporary directory before running the command.
The testbed alone creates containers and publishes their port on 127.0.0.1.
