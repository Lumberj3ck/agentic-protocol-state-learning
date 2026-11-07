# Erlang/OTP SSH target

Pinned official image: `erlang:29.1.2.0-slim`, with its manifest digest in
the Dockerfile. This was the newest stable release listed by the official
Docker Hub `library/erlang` registry on 2026-11-07. The image reports OTP
`29.1.2` in `releases/29/OTP_VERSION` and SSH application `6.0.7` in
`lib/ssh-6.0.7/ebin/ssh.app`.

Registry: https://hub.docker.com/v2/repositories/library/erlang/tags?page_size=100&name=slim

The server runs `ssh:daemon/2` under `erl -noshell`, generates a fresh RSA
host key at startup, and permits only password authentication using
`test` / `test`. Session exec requests return `ok` and exit status zero.
Shell requests are disabled. OTP's default algorithms include
`curve25519-sha256`, strict KEX, `rsa-sha2-256`, `aes128-ctr`,
`hmac-sha2-256`, and compression `none`.

## Validation

Command (Docker config redirected because the host's default builder
activity directory is read-only; pytest cache disabled to keep writes local):

```sh
DOCKER_CONFIG=/tmp/smlearn-erlang-docker SMLEARN_TARGETS=erlang-otp \
  uv run pytest -q tests/test_ssh_mapper.py -p no:cacheprovider
```

Result: **16 passed, 1 skipped**, 60.55 seconds. Raw output: `validation.txt`.

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
| `test_newkeys_without_new_kex_keeps_keys` | SKIP: OpenSSH-only test |
| `test_rekey_after_auth_installs_fresh_keys` | PASS |

A separate mapper trace check decoded the server's `exit-status` channel
request and confirmed status `0`. Exec output was
`CH_SUCCESS+CH_DATA+CH_EOF+CH_REQUEST+CH_CLOSE`.

No behavior differences caused test failures; no mapper changes or protocol
workarounds were needed. The OpenSSH-only case cannot validate this target.

Relevant implementation sources are bundled in the pinned image under
`/usr/local/lib/erlang/lib/ssh-6.0.7/src/`: `ssh_transport.erl`
(`kex_strict_alg/1` and algorithm lists), `ssh_auth.erl`
(`check_password/3` and `get_password_option/2`), and `ssh_cli.erl`
(`exec_direct/6`, `exec_in_self_group/5`, and exit-status handling).
