# Apache MINA SSHD target

Apache MINA SSHD **2.20.1**, the latest stable release listed at
https://mina.apache.org/sshd-project/downloads.html on 2026-11-07.
Version 3.0.0 milestone releases are pre-releases.
The implementation is the official Maven Central artifact
`org.apache.sshd:sshd-core:2.20.1`; transitive dependencies are resolved by its POM.

The multi-stage Docker build compiles a minimal Java server and copies only
classes and runtime dependencies into the official Temurin 21 Alpine JRE image.
The server listens on port 22, uses only password authentication (`test` / `test`),
and accepts session channels and arbitrary exec requests with exit status 0.
An ECDSA P-256 host key is generated on startup before listening and stored in
`/app/hostkey.ser` for the container's lifetime. Generating it before listening
avoids delaying the first KEXINIT beyond the mapper's reset quiet window.
Default MINA transport algorithms and strict KEX behavior are preserved.

## Validation

Run:

```sh
SMLEARN_TARGETS=mina-sshd uv run pytest -q tests/test_ssh_mapper.py
```

In this restricted workspace Docker Buildx cannot write its activity metadata
under `~/.docker`; the validation used `DOCKER_BUILDKIT=0` with the command above.
See `test-output.txt` for the latest test results and `protocol-check.txt` for
the advertised algorithms and a successful exec exchange (exit-status 0).

The initial run had 15 passes, one failure, and one skip: the first connection's
KEXINIT arrived after reset because host-key generation was lazy. Startup key
generation corrected that target configuration issue. No mapper changes were made.

Source reference for initial KEXINIT handling:
`org/apache/sshd/server/session/AbstractServerSession.java`,
`readIdentification()`, in the official source artifact:
https://repo.maven.apache.org/maven2/org/apache/sshd/sshd-core/2.20.1/sshd-core-2.20.1-sources.jar

Final result: **16 passed, 1 skipped**.

| Test | Result |
| --- | --- |
| `test_alphabet_is_complete` | PASS |
| `test_happy_path_completes` | PASS |
| `test_strict_kex_is_negotiated` | PASS |
| `test_wrong_password_fails` | PASS |
| `test_session_works_after_auth` | PASS |
| `test_no_channel_sends_nothing` | PASS |
| `test_disconnect_then_no_conn` | PASS |
| `test_trace_records_packets` | PASS |
| `test_queries_are_deterministic[seq0]` | PASS |
| `test_queries_are_deterministic[seq1]` | PASS |
| `test_queries_are_deterministic[seq2]` | PASS |
| `test_queries_are_deterministic[seq3]` | PASS |
| `test_queries_are_deterministic[seq4]` | PASS |
| `test_queries_are_deterministic[seq5]` | PASS |
| `test_queries_are_deterministic[seq6]` | PASS |
| `test_newkeys_without_new_kex_keeps_keys` | SKIP (OpenSSH-only test) |
| `test_rekey_after_auth_installs_fresh_keys` | PASS |

No unresolved behavior differences or failures attributable to the two known
mapper issues were observed in the final run. All requested target functionality
was validated; the OpenSSH-only test does not apply to this target.
