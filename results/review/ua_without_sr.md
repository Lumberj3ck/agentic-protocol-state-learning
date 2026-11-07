# Skeptical review of D1: USERAUTH_REQUEST without SERVICE_REQUEST

Reviewer, 2026-11-07, about 12:05-12:25 UTC.
Starting position: D1 is a harness artifact until each artifact hypothesis is refuted with evidence.

## Claim under review

Input `KEXINIT KEX30 NEWKEYS UA_PK_OK` (correctly signed publickey USERAUTH_REQUEST for `tester`, no prior SERVICE_REQUEST "ssh-userauth").
Last output: OpenSSH 10.0p1 `UNIMPL`, Dropbear 2025.88 `UA_SUCCESS` (and 2020.81), Go x/crypto/ssh 0.58.0 `NO_CONN`.
Control `KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK`: all three `SR_ACCEPT` then `UA_SUCCESS`.

## Verdict

| Server | Verdict | Behaviour | Decisive evidence |
| --- | --- | --- | --- |
| OpenSSH 10.0p1 | REAL | Replies `SSH_MSG_UNIMPLEMENTED` for seq 3, ignores the request, keeps the connection; a later normal SR+auth on the same connection succeeds | `openssh_core_log_excerpt.txt` (10/10 `dispatch_protocol_error: type 50 seq 3`), `probe_paramiko.json` |
| Dropbear 2025.88 | REAL | Authenticates; the session is fully usable (`exec id` prints `uid=1000(tester)`) | `replay_core_10x.json` server log (10/10 `Pubkey auth succeeded`), `probe_paramiko.json` |
| Go x/crypto/ssh 0.58.0 | REAL | Closes TCP immediately with no DISCONNECT message (`ssh: unexpected message type 50 (expected one of [5])`) | `replay_core_10x.json` server log (10/10), `probe_paramiko.json` (`EOF in transport thread`, no `Disconnect`) |

All files are under `results/review/`.
The disagreement is a confirmed behavioural difference, not a mapper artifact.
It reproduces with an independent client (stock paramiko 5.1.0, different KEX, with and without strict KEX).

## Hypotheses and evidence

### H1: the mapper's UA_PK_OK without SR_AUTH is malformed

Refuted.

- Code: `fuzz_userauth_pk` builds a fresh `AuthHandler` and calls `custom_parse_service_request` (vendor `manualparamiko/auth_handler.py`).
  That function reads only username, auth method, key, the negotiated `server-sig-algs` and `transport.session_id`; nothing in it depends on whether SR_AUTH was sent.
- Wire: `scratch/review/mapper_wire.py` drives the vendored library unchanged, inside a throwaway container of the same `psm-mapper:pinned` image (Python 3.9, paramiko 3.5.0, cryptography 43.0.3), and records every outgoing payload.
  Result `mapper_wire.json`, per server, both modes:
  - USERAUTH_REQUEST payload 878 bytes in both modes, user `tester`, service `ssh-connection`, method `publickey`, has-signature TRUE, algorithm `rsa-sha2-256`, key blob equal to `keys/id_rsa.pub`, no trailing bytes.
  - Signature verified with stock paramiko over the real session id (not the vendored `'SESID'` placeholder): valid in both modes.
  - Sent encrypted with a 32-byte MAC (aes128-ctr + hmac-sha2-256) in both modes.
  - Only difference: outgoing sequence number 3 (no SR) vs 4 (with SR), which is correct.
- Server side confirms correct decryption and parsing: OpenSSH logs `receive packet: type 50` and `dispatch_protocol_error: type 50 seq 3`; Go names message type 50; Dropbear verifies the signature and logs `Pubkey auth succeeded`.
  A bad MAC would have produced a MAC error in each server log; none appears.
- Independent client (`scratch/review/probe_paramiko.py`): stock paramiko 5.1.0 builds the request with its own `AuthHandler._parse_service_accept` (the code a normal paramiko login runs after SERVICE_ACCEPT) and simply never sends the SERVICE_REQUEST.
  Same three outcomes, 2 reps x {strict KEX off, on} per server, with mlkem768x25519-sha256 or curve25519 KEX instead of the mapper's DH group14 (`probe_paramiko.json`).

### H2: Go's NO_CONN is a mapper decode failure or a hidden DISCONNECT

Refuted.

- Go log, 10/10 reps: `handshake error from ...: ssh: unexpected message type 50 (expected one of [5])`.
  Go decrypted the packet, read type 50, and rejected it because only SERVICE_REQUEST (5) is accepted at that point.
- Mapper log: `Sending UA_PK_OK ... got NO_CONN (0.0007s)`; the first read after sending is EOF, no packet came before it.
  The mapper's silent-skip paths for undecodable packets (MAC mismatch 90001, invalid blocking 90000) write `~/self-impl-errorlog.txt` in the mapper container; that file does not exist in any of the three mappers (they run as root, so they could have written it).
- Stock paramiko log: `userauth is OK` then `EOF in transport thread` about 5 ms later, never `Disconnect (code ...)`.
  So Go sends no SSH_MSG_DISCONNECT; it closes the TCP connection.

### H3: OpenSSH's UNIMPL is something else

Refuted.
`docker logs psm-openssh` at DEBUG3 for the 10-rep window: 10/10 `receive packet: type 50`, `dispatch_protocol_error: type 50 seq 3`, `send packet: type 3` (`openssh_core_log_excerpt.txt`).
Before a service is accepted, sshd's dispatch table maps only SERVICE_REQUEST to a handler; everything else goes to the default `dispatch_protocol_error`, which answers UNIMPLEMENTED with the received sequence number (3 is the right number: KEXINIT 0, KEX30 1, NEWKEYS 2, USERAUTH_REQUEST 3).
The connection stays open: with paramiko, a normal SERVICE_REQUEST + publickey auth on the same connection then succeeds and `exec id` works (`probe_paramiko.json`, mode `no_sr_then_sr`).

### H4: timing or nondeterminism

Refuted.

- Determinism: 10/10 identical outputs per server for both the no-SR sequence and the SR control (`replay_core_10x.json`, `deterministic: true` everywhere).
  The 7 extended sequences, 5 reps each, are also deterministic on all three servers (`replay_ext_*.json`).
- Longer wait before the request: `KEXINIT KEX30 NEWKEYS DEBUG DEBUG DEBUG UA_PK_OK` (3 harmless DEBUG messages, about 1.6 s extra) gives the same last output: OpenSSH `UNIMPL`, Dropbear `UA_SUCCESS`, Go `NO_CONN`.
  The paramiko probe waits 0.5 s after NEWKEYS and EXT_INFO and gets the same results.
- Late responses: `KEXINIT KEX30 NEWKEYS UA_PK_OK DEBUG DEBUG DEBUG` gives OpenSSH `UNIMPL NO_RESP NO_RESP NO_RESP` (nothing more arrives and the connection stays open), Dropbear `UA_SUCCESS NO_RESP x3`, Go `NO_CONN x4`.
  The paramiko probe waits 6 s after the request: OpenSSH sends only the UNIMPLEMENTED, and Go closes after about 5 ms.
- Go's close comes 0.7-0.9 ms after the request (mapper log), far inside the 0.3 s read window, so the read window cannot explain it.
- The same split holds for other auth methods without SR: `UA_PK_NOK`, `UA_PW_OK` and `UA_NONE` give OpenSSH `UNIMPL`, Go `NO_CONN`, and Dropbear `UA_FAILURE` / `UA_SUCCESS` / `UA_FAILURE`.
  So OpenSSH and Go react to the message type in that state, not to its content, while Dropbear runs normal authentication.
- Recovery: `KEXINIT KEX30 NEWKEYS UA_PK_OK SR_AUTH UA_PK_OK` gives OpenSSH `UNIMPL SR_ACCEPT UA_SUCCESS+GLOBAL_REQUEST` (the stray request had no effect on state), Go `NO_CONN x3`, and Dropbear `UA_SUCCESS SR_ACCEPT NO_RESP`.
  Dropbear accepts a SERVICE_REQUEST after authentication and then silently ignores the second auth request, as RFC 4252 s5.1 says it SHOULD.

### H5: Dropbear's UA_SUCCESS is cosmetic

Refuted.

- Dropbear log, 10/10 reps: `Pubkey auth succeeded for 'tester' with ssh-rsa key SHA256:vkAr/...` and each of those sessions (pids 32-40) ends with `Exit (tester) ...`, an authenticated exit, not `Exit before auth`.
  The 10th (pid 41) was still open when the log was read; the two `Exit before auth` lines in the window belong to other pids (30, 31), i.e. other connections.
- Stock paramiko, no SERVICE_REQUEST ever sent: `is_authenticated()` is true, then `open_session` + `exec_command("id")` returns `uid=1000(tester) gid=1000(tester) groups=1000(tester)`, in 8/8 no-SR runs (strict KEX on and off) (`probe_paramiko.json`).
  This matches the SR control path exactly.
- `CH_OPEN` through the mapper could not be used because of the mapper bug below; the paramiko probe tests the same thing more thoroughly (channel open, exec, output, exit).
- Dropbear 2020.81 behaves the same through the mapper (`results/replay/smoke_dropbear2020.json`); it was not re-tested here because its containers belong to the running learning job.

### H6 (added): test-config dependence (strict KEX, algorithm choice, host key)

Refuted for strict KEX and KEX algorithm: the paramiko probe agreed strict KEX in half the runs (`strict_kex_agreed` true) and used ML-KEM/curve25519 KEX; outcomes unchanged.
Strict KEX only constrains the initial key exchange, and this request comes after NEWKEYS, so no change was expected.
Not varied: server configuration (each server ran its single pinned config).

## RFC adjudication

- RFC 4253 s10: "After the key exchange, the client requests a service." This describes the client's expected order; it has no MUST and says nothing about what a server does with a request for a service that was never requested.
- RFC 4251 s1 (architecture): "The client sends a service request once a secure transport layer connection has been established." This is also descriptive.
- RFC 4252 s1: "The 'service name' for this protocol is \"ssh-userauth\"." So user authentication is a service a client asks for under RFC 4253 s10, but no clause says that authentication MUST be refused if the service was not requested.
- RFC 4253 s11.4: "An implementation MUST respond to all unrecognized messages with an SSH_MSG_UNIMPLEMENTED message ... Such messages MUST be otherwise ignored." Type 50 is not unrecognized to sshd, only out of place; OpenSSH applies this rule to an out-of-state message. That is permitted (and conservative), not required.
- RFC 4253 s11.1: implementations "SHOULD be able to send" DISCONNECT. Go closing without a DISCONNECT is permitted; sending one would be the SHOULD-friendly choice.
- RFC 4252 s6 (MUST disconnect) covers only message numbers of 80 and higher before authentication; it does not apply to 50.
- Conclusion: none of the three behaviours breaks a MUST.
  OpenSSH and Go enforce the order the architecture describes (strict); Dropbear accepts it out of order (liberal).
  Dropbear's behaviour is a divergence from the protocol's intended order, not an RFC 2119 violation, which fits the NDSS 2023 report and the maintainer's "design choice" (wontfix).
  Security impact appears nil: the signature still covers the session id and the service `ssh-connection`, and the same credentials authenticate on every server.

## Side finding: mapper bug that blocks IGNORE and every channel symbol

While testing H4/H5 the first extended replay crashed both mappers on `KEXINIT KEX30 NEWKEYS IGNORE ...`.
Mapper log: `SSHException: Key-exchange timed out waiting for key negotiation` from `Transport._send_user_message`, then `sys.exit(1)`; Docker restarted `psm-mapper-openssh` and `psm-mapper-dropbear` (RestartCount 1, about 12:16 UTC).
Cause in vendored `manualparamiko/transport.py`: `self.clear_to_send = threading.Event()` is created unset, only `.clear()` is ever called, and the `.set()` in `_parse_newkeys` is commented out.
Every symbol sent through `_send_user_message` therefore blocks for `clear_to_send_timeout` (30 s) and kills the mapper: `IGNORE` (`send_ignore`), `CH_OPEN` (`open_channel`), all `CH_*` channel messages (`channel.py`), and `TCP_FORWARD_*` (`global_request`).
`DEBUG`, `UNIMPL`, `DISCONNECT`, `KEX*`, `SR_*` and `UA_*` use `_send_message` and are not affected.
Consequence: do not put these symbols in a learning alphabet until a patch (for example, P4: send them with `_send_message`) is made and tested; any model or replay that includes them would read the crash as `NO_CONN` or as a mapper error.
The replays in this review use `DEBUG` as the harmless padding input instead of `IGNORE`, and check the authenticated session with the paramiko probe instead of `CH_OPEN`.

## Limits

- One configuration per server; e.g. OpenSSH with non-default `AuthenticationMethods` or Dropbear compile options were not varied.
- The review did not read server source code (none on the box); the dispatch explanation for OpenSSH and Go relies on their own log messages.
- The first extended replay attempt crashed `psm-mapper-openssh` and `psm-mapper-dropbear` once each (the IGNORE bug above); Docker restarted them at about 12:16 UTC, and anyone else using those two mappers at that moment lost their connection.
  `psm-mapper-db2020` and `psm-dropbear2020` were not touched.
- Server logs over a time window can contain lines from other clients using the same container at the same time; counts above use only lines that match our sequence (type 50 / seq 3, `tester` pubkey).

## Files

- `results/review/replay_core_10x.json`: mapper replay, both sequences, 10 reps x 3 servers, with server logs.
- `results/review/replay_ext_openssh_gossh.json`, `results/review/replay_ext_dropbear.json`: timing, recovery and other-auth-method sequences, 5 reps.
- `results/review/mapper_wire.json`: exact USERAUTH_REQUEST fields, sequence numbers and encryption state as sent by the vendored mapper, with and without SR_AUTH.
- `results/review/probe_paramiko.json`: independent stock-paramiko client, modes sr / no_sr / no_sr_then_sr, strict KEX off and on, with client and server logs and `exec id` output.
- `results/review/openssh_core_log_excerpt.txt`: complete OpenSSH DEBUG3 lines for the 10-rep window (the replay JSON keeps only the last 200 log lines).
- Scripts: `scratch/review/mapper_wire.py`, `scratch/review/probe_paramiko.py`, `scratch/review/seqs_core.json`, `scratch/review/seqs_ext.json`.
