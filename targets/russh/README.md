# russh SSH server target

Uses **russh 0.65.1**, the newest stable, non-yanked release in the crates.io
sparse index when checked on 2026-11-07 (published 2026-11-03).
`Cargo.toml` pins the implementation exactly; `Cargo.lock` locks all dependencies.

Registry: https://index.crates.io/ru/ss/russh

Source archive: https://static.crates.io/crates/russh/russh-0.65.1.crate

The program uses russh's server API, with password authentication only (`test` /
`test`), session channels, and an exec handler which acknowledges any command and
returns exit status 0 without executing it. Other authentication handlers retain
russh's rejecting defaults. An ephemeral Ed25519 host key is generated at startup.
Transport preferences retain the library defaults, including curve25519-sha256,
strict KEX, aes128-ctr, hmac-sha2-256, and no compression. The `ring` backend avoids
building the larger default AWS-LC backend; optional RSA and compression features
are unnecessary for this Ed25519 target.

The multi-stage Dockerfile uses an official Rust builder and Debian slim runtime;
the runtime contains only the server binary and Debian's base libraries (about
118 MB uncompressed at validation). It listens on container port 22. Use the
testbed to publish it on loopback only.

Relevant source paths within the exact crate archive:

- `examples/echoserver.rs`: server setup, key generation, and session acceptance.
- `src/server/mod.rs`: handler API, default authentication rejection, exec replies.
- `src/negotiation.rs`: default algorithm lists and strict-KEX persistence on rekey.
- `src/server/encrypted.rs`: channel handling, including the automatic close reply.

Validation:

```sh
SMLEARN_TARGETS=russh uv run pytest -q tests/test_ssh_mapper.py
```

If Docker's default Buildx metadata directory is read-only, use a writable config:

```sh
mkdir -p /tmp/smlearn-russh-docker
DOCKER_CONFIG=/tmp/smlearn-russh-docker SMLEARN_TARGETS=russh uv run pytest -q tests/test_ssh_mapper.py
```

## Validation result (2026-11-07)

The requested suite, with the writable Docker config above, completed:

```text
...............s.                                                        [100%]
16 passed, 1 skipped in 103.33s (0:01:43)
```

| Test | Result |
| --- | --- |
| `test_alphabet_is_complete` | PASS |
| `test_happy_path_completes[russh]` | PASS |
| `test_strict_kex_is_negotiated[russh]` | PASS |
| `test_wrong_password_fails[russh]` | PASS |
| `test_session_works_after_auth[russh]` | PASS |
| `test_no_channel_sends_nothing[russh]` | PASS |
| `test_disconnect_then_no_conn[russh]` | PASS |
| `test_trace_records_packets[russh]` | PASS |
| `test_queries_are_deterministic[russh-seq0]` | PASS |
| `test_queries_are_deterministic[russh-seq1]` | PASS |
| `test_queries_are_deterministic[russh-seq2]` | PASS |
| `test_queries_are_deterministic[russh-seq3]` | PASS |
| `test_queries_are_deterministic[russh-seq4]` | PASS |
| `test_queries_are_deterministic[russh-seq5]` | PASS |
| `test_queries_are_deterministic[russh-seq6]` | PASS |
| `test_newkeys_without_new_kex_keeps_keys[russh]` | SKIP (explicitly OpenSSH-only) |
| `test_rekey_after_auth_installs_fresh_keys[russh]` | PASS |

No failing behavior differences were observed. Neither known mapper issue caused
a failure in this run. Strict KEX negotiation and authenticated rekey both passed.
No mapper, tests, or shared configuration was changed for this target.

An initial invocation could not build because Docker attempted to write Buildx
metadata under the read-only home directory (1 passed, 16 setup errors). Setting
`DOCKER_CONFIG` to `/tmp/smlearn-russh-docker` resolved that environment issue.
