# golang-xcrypto

Pinned implementation: `golang.org/x/crypto v0.58.0`, the latest stable release
reported by the Go module proxy on 2026-11-07. Exact tag commit:
`8fdf07b3114278fb3b78c1cf1814e08bd851eb4c`.
Registry metadata: https://proxy.golang.org/golang.org/x/crypto/@v/v0.58.0.info

The Go 1.26 builder produces a static binary in a scratch runtime (about 6 MB).
An Ed25519 host key is generated at startup. Only test/test password authentication
is configured. Session channels accept exec requests and return exit status zero;
commands are not executed. Algorithm defaults include the mapper's required suite
and strict KEX.

Validation command (BUILDX_CONFIG redirects Docker metadata from the environment's
read-only home directory):

```sh
BUILDX_CONFIG=/tmp/golang-xcrypto-buildx SMLEARN_TARGETS=golang-xcrypto uv run pytest -q tests/test_ssh_mapper.py
```

Result: **15 passed, 1 skipped, 1 failed**. Full pytest output is in
`validation.log`; a single-query reproduction is in `rekey-observation.log`.

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
| test_queries_are_deterministic, seq0 through seq6 (seven cases) | PASS |
| test_newkeys_without_new_kex_keeps_keys | SKIP: OpenSSH-only test |
| test_rekey_after_auth_installs_fresh_keys | FAIL: CH_OPEN returns CLOSED |

## Rekey compatibility finding

The complete failing query returns:

```text
KEXINIT -> NO_RESP
KEX30 -> KEX31+NEWKEYS
NEWKEYS -> NO_RESP
SR_AUTH -> SERVICE_ACCEPT
UA_PW_OK -> UA_SUCCESS
KEXINIT -> KEXINIT
KEX30 -> KEX31+NEWKEYS
NEWKEYS -> NO_RESP
CH_OPEN -> CLOSED
```

x/crypto advertises `kex-strict-s-v00@openssh.com` only in the initial
KEXINIT (`ssh/handshake.go`, lines 542–544), sets strict mode during the
initial exchange (lines 683–688), and retains that mode for subsequent
exchanges. Its transport resets sequence numbers on NEWKEYS whenever
strict mode is active (`ssh/transport.go`, lines 149–155 and 199–206).

Exact upstream sources:

- https://go.googlesource.com/crypto/+/refs/tags/v0.58.0/ssh/handshake.go
- https://go.googlesource.com/crypto/+/refs/tags/v0.58.0/ssh/transport.go

The mapper recomputes `strict_kex_active` on every received KEXINIT
(`src/smlearn/ssh/mapper.py`, line 85). The rekey KEXINIT lacks the marker,
so the mapper stops resetting its sequence numbers while Go continues to
reset them. This explains the closure on the next channel-open packet.
No algorithm mismatch was observed. Per the onboarding rules, no workaround
or mapper modification was made; successful rekey validation remains blocked
by this compatibility difference.
