# wolfSSH target

wolfSSH 1.6.0 (tag `v1.6.0-stable`) with wolfSSL 5.9.4
(tag `v5.9.4-stable`), from the official release tarballs. Both archives
are pinned by SHA-256 in the Dockerfile.

Release references:
- https://github.com/wolfSSL/wolfssh/releases/tag/v1.6.0-stable
- https://github.com/wolfSSL/wolfssl/releases/tag/v5.9.4-stable

The small fork-per-connection server uses wolfSSH's public API. Only password
`test` for user `test` authenticates. Application-driven session channels accept
exec requests and report exit status zero without executing the command.
Other channel requests are rejected by wolfSSH's application-channel defaults.
An ECDSA P-256 host key is generated during image build. Rebuild the image to
rotate it. All SSH protocol parsing and replies come from the unmodified library.

wolfSSL needs `--enable-ssh --enable-curve25519 --enable-aesctr` for the mapper's
algorithms and `--enable-keygen` for wolfSSH's `--enable-all` build. Static
linking also needs `-lm`. Build tools and source trees stay in the build stage.

Public API references (the release tarball's `wolfssh/ssh.h`):
- `wolfSSH_CTX_SetAppChannels`: accept returns after authentication; worker
  drives channel traffic; requests without registered callbacks are rejected.
- `wolfSSH_CTX_SetChannelReqExecCb`: accepts the request through a callback.
- `wolfSSH_stream_exit`: sends exit status, EOF and channel close.
- `wolfSSH_SetUserAuth` and `wolfSSH_SetUserAuthTypes`: enforce password-only auth.

Validation command:

```sh
SMLEARN_TARGETS=wolfssh uv run pytest -q tests/test_ssh_mapper.py
```

In the restricted workspace used for onboarding, prepend
`DOCKER_CONFIG=/tmp/wolfssh-docker` (create that directory first) so buildx can
write its local activity metadata. This changes no Docker networking settings.
Raw validation output is in `validation.txt`.

Validation result: **16 passed, 1 skipped** (85.90 seconds).

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
| `test_newkeys_without_new_kex_keeps_keys` | SKIP: OpenSSH-specific |
| `test_rekey_after_auth_installs_fresh_keys` | PASS |

No blocking implementation behaviour differences were observed. Neither known
mapper issue caused a failure in the final run. Additional protocol checks are
recorded in `protocol-check.txt`: required algorithms, rejection of another
username and the `none` authentication method, and exec exit status zero.
