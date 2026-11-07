# Erlang/OTP 27.3.2 calibration target

Deliberately pinned to OTP **27.3.2**, SSH application **5.2.9**, for the
requested old-version CVE-2025-32433 calibration control. This is not the
latest stable OTP release. No vulnerability probes were performed.

Official image: `docker.io/library/erlang:27.3.2.0-slim`, pinned to manifest
`sha256:eb71f4d1c00ef759d72b2160655c02bd74888713e9e47bed49532da2fe3edd8d`.
Registry metadata: https://hub.docker.com/v2/repositories/library/erlang/tags/27.3.2.0-slim
The image's `releases/27/OTP_VERSION` reports `27.3.2`; the Dockerfile checks
this at build time. Its `lib/ssh-5.2.9/ebin/ssh.app` reports SSH `5.2.9`.

`server.erl` uses `ssh:daemon/2` on port 22, generates an RSA host key at
startup, and enables only password authentication for `test` / `test`.
Session exec uses OTP's direct callback, returning `ok` with successful exit
status for any command. Shell requests are disabled. Default algorithms
include curve25519-sha256, strict KEX, rsa-sha2-256, aes128-ctr,
hmac-sha2-256, and compression none. No protocol workarounds were added.

## Validation

```sh
DOCKER_CONFIG=/tmp/smlearn-erlang-2732-docker PYTHONDONTWRITEBYTECODE=1 \
  SMLEARN_TARGETS=erlang-otp-27.3.2 \
  uv run pytest -q tests/test_ssh_mapper.py -p no:cacheprovider
```

Docker configuration goes to `/tmp` because the host builder's default
activity directory is read-only. Bytecode and pytest cache writes are
disabled to keep generated files out of the protected source/test paths.
Raw output: [validation.txt](validation.txt).

| Test | Result |
| --- | --- |
| test_alphabet_is_complete | PASS |
| test_happy_path_completes | PASS |
| test_strict_kex_is_negotiated | PASS |
| test_wrong_password_fails | PASS |
| test_session_works_after_auth | PASS |
| test_no_channel_sends_nothing | PASS |
| test_disconnect_then_no_conn | PASS |
| test_trace_records_packets | PASS |
| test_queries_are_deterministic[seq0] | PASS |
| test_queries_are_deterministic[seq1] | PASS |
| test_queries_are_deterministic[seq2] | PASS |
| test_queries_are_deterministic[seq3] | PASS |
| test_queries_are_deterministic[seq4] | PASS |
| test_queries_are_deterministic[seq5] | PASS |
| test_queries_are_deterministic[seq6] | PASS |
| test_newkeys_without_new_kex_keeps_keys | SKIP (OpenSSH-only) |
| test_rekey_after_auth_installs_fresh_keys | PASS |

**16 passed, 1 skipped in 78.16 seconds.** No behavior differences caused
failures. Neither of the two anticipated mapper issues caused a failure in
this run. No mapper, tests, or documentation outside this target was edited.
The OpenSSH-only test does not apply to this target.

Implementation references bundled in the exact pinned image, under
`/usr/local/lib/erlang/lib/ssh-5.2.9/src/`:

- `ssh_transport.erl`: algorithm declarations at lines 206–267;
  `kex_strict_alg/1` at 890–891; `maybe_reset_sequence/2` at 2253–2256.
- `ssh_auth.erl`: `check_password/3` at 507 and
  `get_password_option/2` at 542 enforce the configured password list.
- `ssh_cli.erl`: `exec_direct/6` at 794 and `exec_in_self_group/5` at 821
  implement direct exec callbacks; exit-status handling is at 320–325.
