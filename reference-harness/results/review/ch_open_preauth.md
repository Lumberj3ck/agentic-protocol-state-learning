# Skeptical review of D2: CHANNEL_OPEN before authentication

Reviewer, 2026-11-07, about 12:28-13:10 UTC.
Starting position: D2 is a harness artifact until each artifact hypothesis is refuted with evidence.

## Claim under review

After key exchange, with or without `SR_AUTH`, a `CH_OPEN` (SSH_MSG_CHANNEL_OPEN "session", message 90) sent before authentication gives:
OpenSSH 10.0p1 `UNIMPL` and the connection stays open; Dropbear 2025.88 `NO_CONN`; Go x/crypto/ssh 0.58.0 `NO_CONN`.
Control `KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK CH_OPEN`: `CH_OPEN_SUCCESS` on all three.
RFC 4252 s6: "Message numbers of 80 and higher are reserved for protocols running after this authentication protocol, so receiving one of them before authentication is complete is an error, to which the server MUST respond by disconnecting, preferably with a proper disconnect message sent to ease troubleshooting."

## Verdict

| Server | Verdict | Behaviour | Decisive evidence |
| --- | --- | --- | --- |
| OpenSSH 10.0p1 | REAL | Answers every pre-auth message >= 80 (90, 80, 94, 98 tested) with `SSH_MSG_UNIMPLEMENTED` carrying the right sequence number, ignores it and keeps the connection; normal auth and a channel then work; it closes only at LoginGraceTime, exactly like an idle connection | `ch_open_openssh_log_excerpt.txt`, `ch_open_probe.json`, `ch_open_probe_grace.json`, `ch_open_replay_openssh.json`; source `auth2.c` `do_authentication2()` + `dispatch.c` `dispatch_protocol_error()` |
| Dropbear 2025.88 | REAL | Closes TCP within about 1-2 ms, no SSH_MSG_DISCONNECT; log `Exit before auth ...: Received message 90 before userauth` (80 for GLOBAL_REQUEST) | `ch_open_replay_dropbear.json` (10/10 per sequence), `ch_open_probe.json` (`EOF in transport thread`, never `Disconnect`); source `process-packet.c` `process_packet()` |
| Go x/crypto/ssh 0.58.0 | REAL | Closes TCP immediately, no SSH_MSG_DISCONNECT; log `ssh: unexpected message type 90 (expected one of [5])`, or `[50]` after SR_AUTH | `ch_open_replay_gossh.json`, `ch_open_probe.json`; source `server.go` `serverHandshake()` / `NewServerConn()` |

All files are under `results/review/` unless a path is given.
The disagreement is a confirmed behavioural difference, not a mapper artifact.
It reproduces with an independent client (stock paramiko 5.1.0, curve25519/ML-KEM KEX, strict KEX on, sequence numbers reset) and with the mapper (DH group14, no strict KEX), and it is explained line by line by each server's source.
On the RFC: Dropbear and Go meet the MUST of RFC 4252 s6 (they disconnect; neither sends the "preferable" DISCONNECT message).
OpenSSH violates the letter of that MUST, with no security impact found (details at the end).

## Q1: is the mapper's CH_OPEN correct, and is P5 sound?

### Wire view

`scratch/review/ch_open_wire.py` drives the vendored library unchanged, in a throwaway container of the `psm-mapper:pinned` image (same Python 3.9 / cryptography 43.0.3 as the mappers), and records every outgoing payload; payloads are parsed with stock paramiko 3.5.0 (`ch_open_wire.json`).
For each server and each of `... CH_OPEN` (no SR), `... SR_AUTH CH_OPEN`, `... SR_AUTH UA_PK_OK CH_OPEN` (control) and `... TCP_FORWARD_START`:

- CHANNEL_OPEN payload: kind `session`, sender channel 0, initial window 2097152, max packet 32768, 0 trailing bytes.
- The CHANNEL_OPEN payload is byte-identical before and after authentication (`ch_open_payload_identical_pre_vs_post: true` for all three servers); the control proves those exact bytes are accepted (`CH_OPEN_SUCCESS`).
- Sent encrypted (aes128-ctr) with a 32-byte MAC, outgoing sequence numbers 3 (no SR), 4 (SR), 5 (after auth): correct.
- GLOBAL_REQUEST (TCP_FORWARD_START): `tcpip-forward`, want_reply true, `0.0.0.0`, port 0, 0 trailing bytes, sequence 3, encrypted.
- Every server decrypted and recognised the message, so a MAC or framing error is excluded:
  OpenSSH logs `receive packet: type 90` / `dispatch_protocol_error: type 90 seq 3` (and `seq 4` with SR); Dropbear names "message 90"; Go names "message type 90".

### P5

P5 replaces the body of `Transport._send_user_message` with `if not self.active: return; self._send_message(data)`.
`_send_message` is the function every other mapper symbol (KEX*, SR_*, UA_*, DEBUG, all CH_* except CH_OPEN, TCP_FORWARD_*) already uses, so CH_OPEN and IGNORE now go through the same packetizer path as the inputs that were already trusted.
What else could change:

- The `active` guard: the mapper sets `transport.active = True` and never starts the Transport thread, so it stays true; the instrumented runs record `active: true` for every call and a duration of 0.1-0.3 ms (`send_user_message_calls` in `ch_open_wire.json`). A silently dropped CH_OPEN is excluded, and the server logs show the packet arrived.
- The removed lock (`clear_to_send_lock`) only serialises against paramiko's reader thread, which the mapper does not run.
- One side effect beyond unblocking: when an old Transport with an open channel is garbage-collected, `Channel.__del__` -> `close()` now sends CHANNEL_EOF + CHANNEL_CLOSE through `_send_user_message` without waiting.
  Observed in `ch_open_wire.json` (dropbear `post_auth_ch_open`: calls of type 96, 97 belonging to an earlier connection; openssh `post_auth_ch_open`: types 96/97 at seq 6/7 recorded after that connection's socket was closed).
  These go to the old, already closed socket (`process_reset` closes it before a new Transport is built); the vendored packetizer swallows the resulting EOFError, so nothing reaches any server.
  Harmless, but it is a behaviour change that the P5 note does not mention.
- Correction to `vendor/PATCHES.md` P5 and to the previous review: `TCP_FORWARD_*` were never affected by the `clear_to_send` bug; `fuzz_global_request_tcp(_cancel)` call `_send_message` directly.
  Only `IGNORE` (`send_ignore`) and `CH_OPEN` (`open_channel`) used `_send_user_message`.

Conclusion: P5 is sound for this claim; it changes timing (no 30 s block) and nothing on the wire.

## Q2: OpenSSH

### Logs

OpenSSH DEBUG3, review window 12:33-12:47 UTC (`ch_open_openssh_log_excerpt.txt`, filtered to dispatch / DISCONNECT / grace lines):
`dispatch_protocol_error: type 90 seq 3 [preauth]` (no SR), `type 90 seq 4` (after SR), `type 90 seq 5` (after a failed UA_PK_NOK, 10 lines = 10 reps), `type 90 seq 6` (after three DEBUG, 10 lines = 10 reps), `type 80 seq 3` / `type 80 seq 4` (GLOBAL_REQUEST, 10 reps for seq 4), `type 98 seq 4` and `type 94 seq 5` (CHANNEL_REQUEST, CHANNEL_DATA from the paramiko probe), each followed by `send packet: type 3`.
The paramiko probe uses strict KEX, so its sequence numbers restart at 0 after NEWKEYS (`type 90 seq 0`, `seq 1`, `seq 2`).
The sequence numbers match our sequences exactly, so these lines are ours and not the concurrent learners'.

### Source (openssh-portable tag V_10_0_P1)

- `auth2.c` `do_authentication2()`: `ssh_dispatch_init(ssh, &dispatch_protocol_error)`, then only `SSH2_MSG_SERVICE_REQUEST` (and `SSH2_MSG_EXT_INFO`) get handlers; `input_service_request()` later adds `SSH2_MSG_USERAUTH_REQUEST`.
  Every other message type, including all of 80-127, is dispatched to the default.
- `dispatch.c` `dispatch_protocol_error()`: `logit("dispatch_protocol_error: type %d seq %u")`, sends `SSH2_MSG_UNIMPLEMENTED` with the sequence number, returns 0, so `ssh_dispatch_run()` keeps reading.
  The payload is never parsed.
- `serverloop.c` `server_init_dispatch()` installs `server_input_channel_open`, `server_input_global_request` etc. only after authentication, in the post-auth process; the pre-auth (privsep, unprivileged) process has no channel handlers at all.
- `dispatch.c` `ssh_dispatch_run()` sends `DISCONNECT "protocol error: rcvd type %d"` only when the handler slot is NULL, which is the case during the initial key exchange (before `do_authentication2` fills the table).
  This explains a second, consistent observation: `KEXINIT CH_OPEN` gives `KEXINIT NO_CONN` on OpenSSH (10/10, `ch_open_replay_openssh.json`; `CH_OPEN` as the very first input only shows the server's KEXINIT because the sequence ends there), and the window contains `sending SSH2_MSG_DISCONNECT: protocol error: rcvd type 90` lines.
  Those come from type 90 during the initial KEX (our 20 such replays plus the B_* learning runs, whose alphabet now includes CH_OPEN); our post-KEX CH_OPENs never produced a DISCONNECT (mapper never saw one, paramiko never logged `Disconnect (code ...)`).
- `packet.c` `ssh_packet_read_poll2()` disconnects by type only for `type < SSH2_MSG_MIN`; there is no "type >= 80 before auth" check anywhere.

### Is the connection really usable afterwards?

Yes (stock paramiko, `ch_open_probe.json`, 2 reps per mode):

- `ch_open_then_auth`: CHANNEL_OPEN for channel 7, UNIMPLEMENTED, then normal SERVICE_REQUEST + publickey auth succeeds, `open_session` + `exec id` returns `uid=1000(tester) gid=1000(tester) groups=1000(tester)`.
  No CHANNEL_OPEN_CONFIRMATION or FAILURE ever arrives for channel 7, before or after auth (`late_replies_for_preauth_channels: []`): the pre-auth request was not queued or replayed.
- `many_then_auth`: three CHANNEL_OPENs, a GLOBAL_REQUEST, a CHANNEL_REQUEST (98) and a CHANNEL_DATA (94), each answered with UNIMPLEMENTED (6 per run), then 10 s of waiting with the connection open, then auth + `exec id` succeed.
- Mapper: `KEXINIT KEX30 NEWKEYS CH_OPEN SR_AUTH UA_PK_OK` gives `... UNIMPL SR_ACCEPT UA_SUCCESS+GLOBAL_REQUEST`, 10/10.

### Does OpenSSH disconnect later?

No, other than at LoginGraceTime, and that is not caused by the CH_OPEN (`ch_open_probe_grace.json`).
Two parallel connections, one with a pre-auth CHANNEL_OPEN and one idle: closed after 121.6 s and 121.8 s (LoginGraceTime default 120 s plus up to 4 s jitter), both with `Timeout before authentication` (pids 917, 918) and no DISCONNECT message.
Repeated messages (3 CHANNEL_OPENs plus 3 other types >= 80) and a 3 x DEBUG delay before or after the CH_OPEN do not change anything.

### General behaviour for messages >= 80

Yes: GLOBAL_REQUEST (80) via the mapper's `TCP_FORWARD_START` (code checked: `_send_message`, unaffected by P5, reply types all in `MSG_NAMES`) gives `UNIMPL` 10/10, with and without SR_AUTH; CHANNEL_REQUEST (98) and CHANNEL_DATA (94) via paramiko also give UNIMPLEMENTED.
The behaviour is OpenSSH's generic pre-auth default handler, not something specific to CHANNEL_OPEN.

## Q3: Dropbear and Go: is a DISCONNECT being missed?

No.

- Stock paramiko logs `Disconnect (code N): ...` whenever it receives SSH_MSG_DISCONNECT; for both servers every pre-auth run (5 modes x 2 reps = 10 per server) logs only `EOF in transport thread` (`ch_open_probe.json`).
- Mapper: the first read after sending is EOF, `got NO_CONN` in under 5 ms (`docker logs psm-mapper-dropbear` since 12:37 UTC: 90 of 90 post-KEX pre-auth CH_OPENs and 20 of 20 TCP_FORWARD_STARTs; the same 90 of 90 and 20 of 20 on `psm-mapper-gossh`).
  A DISCONNECT would have produced the output `DISCONNECT`; an undecodable packet would have written `~/self-impl-errorlog.txt`, which does not exist in any of the three mapper containers.
- Dropbear source (tag DROPBEAR_2025.88) `src/process-packet.c` `process_packet()`: `if (!ses.authstate.authdone && type > MAX_UNAUTH_PACKET_TYPE) dropbear_exit("Received message %d before userauth", type);` with `MAX_UNAUTH_PACKET_TYPE = SSH_MSG_USERAUTH_PK_OK` (60).
  `svr_dropbear_exit()` logs `Exit before auth`, optionally sleeps `UNAUTH_CLOSE_DELAY` (default 0) and calls `session_cleanup()`; no DISCONNECT is sent.
  This is an explicit implementation of RFC 4252 s6 (with the threshold at 60 rather than 80).
  Logs: 10/10 `Received message 90 before userauth` for every CH_OPEN sequence and 10/10 `Received message 80 before userauth` for TCP_FORWARD_START (`ch_open_replay_dropbear.json`); before KEX: `Unexpected packet type 90, expected 20` / `expected 30`.
- Go source (golang.org/x/crypto v0.58.0) `ssh/server.go`: after NEWKEYS `serverHandshake()` reads one packet and `Unmarshal(packet, &serviceRequest)` fails with `unexpected message type 90 (expected one of [5])`; inside `serverAuthenticate()` the same happens with `userAuthRequestMsg` (`expected one of [50]`).
  `NewServerConn()` then calls `c.Close()` and returns the error; no DISCONNECT is written on this path (Go writes one only for too many auth failures/attempts).
  Logs, 10/10 per sequence (`ch_open_replay_gossh.json`): `unexpected message type 90 (expected one of [5])` without SR, `[50]` after SR_AUTH or after UA_PK_NOK, `unexpected message type 80` for TCP_FORWARD_START; before KEX `first packet should be msgKexInit` and `expected one of [30]`.
  Go therefore disconnects on any unexpected message before authentication, not specifically on >= 80; for messages >= 80 the result coincides with RFC 4252 s6.

## Q4: determinism

Mapper replay, 10 reps per sequence per server, 13 sequences (`scratch/review/ch_open_seqs_all.json`), all deterministic:

| Sequence | OpenSSH | Dropbear | Go |
| --- | --- | --- | --- |
| `KEXINIT KEX30 NEWKEYS CH_OPEN` | `... UNIMPL` | `... NO_CONN` | `... NO_CONN` |
| `... SR_AUTH CH_OPEN` | `SR_ACCEPT UNIMPL` | `SR_ACCEPT NO_CONN` | `SR_ACCEPT NO_CONN` |
| `... SR_AUTH UA_PK_OK CH_OPEN` (control) | `UA_SUCCESS+GLOBAL_REQUEST CH_OPEN_SUCCESS` | `UA_SUCCESS CH_OPEN_SUCCESS` | `UA_SUCCESS CH_OPEN_SUCCESS` |
| `... CH_OPEN SR_AUTH UA_PK_OK` | `UNIMPL SR_ACCEPT UA_SUCCESS+GLOBAL_REQUEST` | `NO_CONN x3` | `NO_CONN x3` |
| `... CH_OPEN DEBUG DEBUG DEBUG` | `UNIMPL NO_RESP x3` | `NO_CONN x4` | `NO_CONN x4` |
| `... DEBUG DEBUG DEBUG CH_OPEN` | `NO_RESP x3 UNIMPL` | `NO_RESP x3 NO_CONN` | `NO_RESP x3 NO_CONN` |
| `... TCP_FORWARD_START` | `UNIMPL` | `NO_CONN` | `NO_CONN` |
| `... SR_AUTH TCP_FORWARD_START` | `SR_ACCEPT UNIMPL` | `SR_ACCEPT NO_CONN` | `SR_ACCEPT NO_CONN` |
| `... SR_AUTH UA_PK_NOK CH_OPEN` | `UA_FAILURE UNIMPL` | `UA_FAILURE NO_CONN` | `UA_FAILURE NO_CONN` |
| `... CH_OPEN CH_OPEN` | `UNIMPL CH_MAX` (mapper artifact, see below) | `NO_CONN CH_MAX` (artifact) | `NO_CONN CH_MAX` (artifact) |
| `... CH_OPEN SR_AUTH UA_PK_OK CH_OPEN` | `UNIMPL SR_ACCEPT UA_SUCCESS+GLOBAL_REQUEST CH_MAX` (artifact) | `NO_CONN x3 CH_MAX` (artifact) | `NO_CONN x3 CH_MAX` (artifact) |
| `CH_OPEN` (before KEX) | `KEXINIT` (the server's own KEXINIT arrives in that read window) | `KEXINIT` | `KEXINIT` |
| `KEXINIT CH_OPEN` | `KEXINIT NO_CONN` | `KEXINIT NO_CONN` | `KEXINIT NO_CONN` |

(`...` = `KEXINIT KEX31+NEWKEYS+EXT_INFO NO_RESP`.)
The earlier 3-rep evidence (`results/replay/p5_ch_open_ignore.json`) is consistent; the paramiko probe adds 2 reps per mode per server with the same outcome.

## Q5: prior work

Nobody has classified this as an RFC 4252 s6 violation, as far as a short search found; the behaviour is visible in published models and was left unremarked.

- Bäumer, Maehren, Brinkmann, Schwenk, CCS 2025 (arXiv 2509.10895): the paper's scope stops at SERVICE_ACCEPT ("we only investigate the beginning of the server's SSH state machine"); RFC 4252 s6 is not discussed.
  Their published OpenSSH 9.9p2 ECDH model (github.com/RUB-NDS/SSH-Strict-Kex-Violations-State-Learning-Artifacts, `openssh_9.9p2_ecdh/localhost_TRANSPORT_long.dot`) has, after NEWKEYS (s5) and after SERVICE_ACCEPT (s6), `MSG_CHANNEL_OPEN_SESSION / UnimplementedMessage` and `MSG_GLOBAL_REQUEST_TCPIP_FORWARD / UnimplementedMessage` self-loops: the same behaviour on 9.9p2.
  Their Dropbear 2025.87 and Go 0.37.0 models go from that state on `MSG_CHANNEL_OPEN_SESSION / [No output]` to a different (sink) state, consistent with our NO_CONN.
  The only related passage is about LANCOM answering "message IDs greater than or equal to 50 with UNIMPLEMENTED" during the handshake (a strict-KEX issue, not pre-auth).
- Fiterau-Brostean, Lenaerts, Poll, SPIN 2017: their OpenSSH 6.9p1 model labels the auth-layer states with `CH_*, KEXINIT, KEX30 / UNIMPL`; no property covers it (property 4 only requires that a successful channel open follows UA_SUCCESS, which holds).
  For other "UNIMPL instead of the RFC's output" cases they wrote "Whether the alternative behavior adapted is acceptable is up for debate."
- Fiterau-Brostean et al., NDSS 2023: no bug pattern for connection-layer messages before auth; not among the OpenSSH 8.8p1 findings.
  Their report to openssh-unix-dev (2021-10, https://lists.mindrot.org/pipermail/openssh-unix-dev/2021-October/039790.html) lists "Issue 4. Use of UNIMPLEMENTED when the RFC says otherwise (very minor ...)" for other triggers, and says "None of the issues appear to have any security implications"; no reply is archived.
- OpenSSH bugzilla could not be searched directly (login redirect); web search found nothing relevant.
  The `dispatch_protocol_error` default handler for pre-auth is old (same in OpenSSH 5.2).

## Q6: RFC adjudication

- RFC 4252 s6 is the specific rule for exactly this input: message number >= 80 before authentication is complete "is an error, to which the server MUST respond by disconnecting, preferably with a proper disconnect message".
- RFC 4253 s11.4 ("MUST respond to all unrecognized messages with an SSH_MSG_UNIMPLEMENTED message ... Such messages MUST be otherwise ignored") is the general rule for unrecognised message numbers.
  The counter-argument for OpenSSH is that its pre-auth process genuinely does not implement the connection protocol, so 90 is "unrecognised" there; but 90 is a defined message that sshd implements, and the specific 4252 s6 rule governs this case over the general 4253 s11.4 one.
- So OpenSSH 10.0p1 violates the letter of RFC 4252 s6 (no disconnect), and has done so since at least 6.9p1 (SPIN 2017) and 9.9p2 (BMBS25 artifact).
- Dropbear and Go satisfy the MUST (they disconnect); both skip the "preferably" DISCONNECT message, which is permitted (RFC 4253 s11.1 makes sending DISCONNECT a SHOULD-level capability).
- Security impact: none found.
  OpenSSH never parses the payload (`dispatch_protocol_error` only logs type and sequence number), the pre-auth process has no channel code, no channel is created or queued (no late confirmation after auth), the authentication state is unchanged (later auth behaves exactly as without the message), and the connection still ends at LoginGraceTime.
  An unauthenticated client gains nothing but one UNIMPLEMENTED reply per packet; it could keep a pre-auth connection busy with junk, but it can do the same with IGNORE or DEBUG, so the resource cost is not new.
- Calibrated label: OpenSSH = "violation of the letter of a MUST (RFC 4252 s6), no security impact"; Dropbear, Go = compliant (no disconnect message, which is allowed).

## Side findings for the harness (affect learning with CH_* symbols)

1. CH_MAX abstraction artifact.
   `fuzz_channel_open` registers the channel locally before any reply and never removes it when the server answers UNIMPLEMENTED or closes, and a second `CH_OPEN` returns `CH_MAX` without sending anything.
   Consequence on OpenSSH: `... CH_OPEN SR_AUTH UA_PK_OK CH_OPEN` gives `CH_MAX`, whereas the server would accept the channel (paramiko `ch_open_then_auth` opens one).
   A model learned with `CH_OPEN` in the alphabet (the running B_openssh learner has it) will contain mapper-made states that remember "a pre-auth CH_OPEN was sent"; any diff involving `CH_MAX` must not be reported as server behaviour.
   On Dropbear/Go the same artifact appears after `NO_CONN` (`NO_CONN CH_MAX`); `psm/robust_sul.py`'s NO_CONN sink shortcut should mask it during learning, but not in plain replays.
2. All other CH_* inputs crash the mapper (found by reading code, not sent).
   `get_remote_chanid_fuzz()` does `self._channels._map[self._channels._map.keys()[0]]`; `_map` is a plain dict, so on Python 3 this raises `TypeError` ('dict_keys' object is not subscriptable), not the `IndexError` it catches, and `process_learlib_query` calls `sys.exit(1)`.
   This affects `CH_CLOSE`, `CH_EOF`, `CH_DATA`, `CH_EXTENDED_DATA`, `CH_REQUEST_PTY`, `CH_REQUEST_ENV`, `CH_WINDOW_ADJUST`, with or without an open channel; `CH_CLOSE` would also pop the local channel first.
   Do not put these in an alphabet before a patch (e.g. `next(iter(...))` with an emptiness check) and a test.
3. `vendor/PATCHES.md` P5 text overstates its scope (TCP_FORWARD_* were never blocked) and omits the `Channel.__del__` EOF/CLOSE side effect (harmless, see Q1).

## Limits

- One configuration per server; OpenSSH's `LoginGraceTime` was left at its default and observed, not varied.
- The OpenSSH, Dropbear and Go servers were shared with the running learners (B_openssh, B_dropbear with CH_OPEN in the alphabet) and another replay; log windows contain their lines, so counts above use only lines whose content and sequence number match our inputs.
  The replay JSON keeps only the last 200 log lines per sequence, which at DEBUG3 is less than one rep; `ch_open_openssh_log_excerpt.txt` is the complete filtered window.
- My first Go replay timed out (120 s) because another replay (`results/diff/A_dropbear_vs_gossh_seqs.json`) held `psm-mapper-gossh`; no mapper crashed (RestartCount 0 on all three), and the Go replay was rerun alone afterwards.
- In `ch_open_probe.json` the `wire` list can miss the first incoming packet after instrumentation (paramiko's reader thread was already inside the unwrapped `read_message`); the paramiko log (`Oops, unhandled type 3`, `Disconnect`, `EOF`) is complete and is what the conclusions above use.
- The search for prior reports was short; OpenSSH bugzilla was not searchable without login.

## Files

- `results/review/ch_open_wire.json`: mapper wire view (payload fields, sequence numbers, encryption, P5 call records), 4 sequences x 3 servers.
- `results/review/ch_open_probe.json`: stock paramiko 5.1.0, modes `ch_open`, `sr_ch_open`, `global_req`, `ch_open_then_auth`, `many_then_auth`, 2 reps x 3 servers, with paramiko logs and server logs.
- `results/review/ch_open_probe_grace.json`: OpenSSH, pre-auth CH_OPEN vs idle, waited until close.
- `results/review/ch_open_replay_openssh.json`, `ch_open_replay_dropbear.json`, `ch_open_replay_gossh.json`: mapper replays, 13 sequences x 10 reps.
- `results/review/ch_open_openssh_log_excerpt.txt`: OpenSSH dispatch / DISCONNECT / grace lines for 12:33-12:47 UTC.
- Scripts: `scratch/review/ch_open_wire.py`, `scratch/review/ch_open_probe.py`, `scratch/review/ch_open_seqs_all.json`.
