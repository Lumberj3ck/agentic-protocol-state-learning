# Skeptical review of the KEX-phase disagreements K1-K4

Reviewer, 2026-11-07, about 15:10-15:25 (laptop time).
Starting position: every claim is a harness artifact until each artifact hypothesis is refuted with evidence.
Claims under review: the A_threeway sequences in `results/final/verified_all.md` rows 28, 29, 32, 33, 38, 40, 44, 46, 51, 52, 56-58, 62-64 (`results/replay/A_threeway_replay.json`, 5/5 deterministic on all three servers).
In each, OpenSSH 10.0p1 answers UNIMPLEMENTED and keeps the connection; Dropbear 2025.88 and Go x/crypto/ssh 0.58.0 close TCP without SSH_MSG_DISCONNECT.
Not redone here: the generic hypotheses G1-G4 of `remaining_classes.md` (late DISCONNECT, NO_CONN hiding, rate limits, mapper crash), the correctness of the mapper's SR_AUTH / UA_PK_OK bytes (`ua_without_sr.md`), and the C4 findings on NEWKEYS-before-KEX30 and duplicate KEX30.
All files are under `results/review/` unless a path is given.

## Verdicts

| Claim | OpenSSH 10.0p1 | Dropbear 2025.88 | Go 0.58.0 | Strict KEX changes it? | RFC adjudication |
| --- | --- | --- | --- | --- | --- |
| K1 duplicate KEXINIT, initial KEX | REAL: UNIMPL, KEX completes, session usable | REAL: exit, no DISCONNECT | REAL: close, no DISCONNECT | Yes, for OpenSSH: DISCONNECT "strict KEX violation"; then all three terminate | Unspecified divergence; strict-KEX-only requirement |
| K2 SERVICE_REQUEST, initial KEX | REAL: UNIMPL, KEX completes, session usable | REAL: exit | REAL: close | Yes, for OpenSSH, as K1 | Unspecified divergence; strict-KEX-only requirement |
| K3 KEX30 / NEWKEYS outside any KEX | REAL: UNIMPL, session usable (non-strict) | REAL: exit | REAL: close | No (strict KEX covers only the initial KEX) | Unspecified divergence; no requirement anywhere |
| K4 duplicate KEXINIT / SR / USERAUTH during a post-auth rekey | REAL: UNIMPL, rekey completes, session usable | REAL: exit | REAL: close | No (rekey) | Unspecified divergence; RFC 4253 s7.1 binds only the sender |

No claim is an artifact.
One qualification applies to K1 and K2: OpenSSH's UNIMPLEMENTED is its legacy, non-strict branch.
The mapper never negotiates strict KEX, so the models describe that branch only.
Current clients (OpenSSH, paramiko >= 3.4) negotiate strict KEX, and against them all three servers terminate on K1 and K2; the remaining difference is that only OpenSSH sends a DISCONNECT.

## Evidence and tools

- `kexp_wire.json` / `kexp_wire.log` (script `scratch/review/kexp_wire.py`, reusing `rc_wire.run()` unchanged): the vendored mapper in a throwaway `psm-mapper:pinned` container against the three servers behind mappers 8001-8003 (ports 2201-2203).
  11 sequences x 3 servers; per step every packet sent (type, outgoing seq, encrypted or not, KEXINIT bytes) and received (UNIMPL's rejected seq), plus a 2 s late read.
- `kexp_probe.json` / `kexp_probe.log` (script `scratch/review/kexp_probe.py`, reusing `rc_probe.py`'s instrumentation): stock paramiko 5.1.0, i.e. an independent client with fresh cookies and ML-KEM768x25519 KEX instead of the mapper's DH group14.
  17 modes x strict KEX {off, on} x 3 servers, 1 rep each (102 connections), with the server log window per connection.
  Where the connection survives, the probe authenticates and runs `exec id` on the same connection.
- Server log windows of the claimed sequences: `results/replay/A_threeway_replay.json` (48 windows: 16 sequences x 3 servers).
- `kexp_source_excerpts.txt`: the cited source lines (openssh-portable V_10_0_P1, dropbear DROPBEAR_2025.88, golang/crypto v0.58.0), RFC 4253 s7.1/s7.3/s11.4, and draft-ietf-sshm-strict-kex-01 s3.2-3.3.

## (a) Is any of this caused by the mapper?

- **A1: the mapper sends malformed bytes or uses the wrong keys.** Refuted.
  - Wire: every disputed packet leaves with the expected type and sequence number, in plaintext before the first NEWKEYS and encrypted after it (`kexp_wire.json`, e.g. `k1_dup` `(20, seq 1, plaintext)`, `k3_kex30` `(30, seq 3, encrypted)`, `k4_ua` `(50, seq 6, encrypted)`).
    OpenSSH's UNIMPLEMENTED names exactly that sequence number in every case.
  - Server logs name the message type and sequence number, which a server can only do after decrypting the packet and checking its MAC.
    OpenSSH: `kex_protocol_error: type 20 seq 1 [preauth]`, `type 5 seq 2 [preauth]`, `dispatch_protocol_error: type 30 seq 3 [preauth]`, `type 21 seq 5`, `kex_protocol_error: type 20 seq 6`, `dispatch_protocol_error: type 50 seq 7`, and so on.
    Dropbear: `Unexpected packet type 20, expected 30`, `Unexpected packet type 5, expected 21`, `Premature kexdh_init message received`, `Unexpected newkeys message`, `Unexpected packet type 50, expected 30`.
    Go: `ssh: unexpected message type 20 (expected one of [30])`, `unexpected message type 5 (expected 21)`, `unexpected message type 30 (expected one of [5])`, `ssh: got bogus newkeys message`.
  - None of the 48 claim log windows contains `Integrity`, `Bad packet length`, `corrupt`, `message authentication code incorrect` or similar (grep count 0).
- **A2: P4 (one KEXINIT cookie per connection) makes the duplicate KEXINIT a replay that Dropbear and Go reject.** Refuted.
  - Wire: the mapper's duplicate KEXINIT is indeed byte-identical to its first one, cookie included (`all_kexinits_identical_incl_cookie: true` for `k1_dup`, `k1_dup_after30`, `k4_dup` on all three servers).
  - Paramiko with a fresh cookie (`k1_dupfresh_before30`, `k1_dupfresh_after30`, `k4_dupfresh_*`) and with a byte-identical copy (`k1_dupsame_before30`) gets the same answer on every server: OpenSSH UNIMPLEMENTED (seq 1 / 2) and the KEX completes; Dropbear and Go close.
  - Source: neither Dropbear nor Go looks at the payload.
    Dropbear rejects by message type in `process-packet.c:90-115` (`requirenext` check), before `recv_msg_kexinit` runs.
    Go's `dhGroup.Server` (`kex.go:155-164`) reads exactly one packet and fails to unmarshal it as KEXDH_INIT; after KEX30 `enterKeyExchange` (`handshake.go:759-762`) expects NEWKEYS.
- **A3: the mapper's own state after the first message (auto-KEXINIT, NEWKEYS taint).** Does not apply.
  - Every claim starts with the input KEXINIT, so the automatic KEXINIT (`PATCHES.md`) never fires.
  - K3's second NEWKEYS is the NEWKEYS-without-KEX case of `psm/taint.py`, but the disagreement is at that NEWKEYS's own output, which is correct: the packet is sent under the current keys (`k3_newkeys` `(21, seq 3, encrypted)`), OpenSSH answers `UNIMPLEMENTED seq 3`, Dropbear logs `Unexpected newkeys message`, Go logs `got bogus newkeys message`.
    Only later inputs would be garbage, and the claimed sequences end at that NEWKEYS.
  - The mapper cannot show that OpenSSH really ignored the stray NEWKEYS (it corrupts its own outbound stream afterwards); paramiko can, because it does not switch keys on a raw NEWKEYS.
    Non-strict paramiko `k3_newkeys_{pre,sr,auth}` on OpenSSH: `UNIMPLEMENTED seq 3/4/5`, then publickey auth and `exec id` succeed on the same connection.
- **A4: the close is late, or a reply is late.** Refuted.
  The 2 s late read after the last step is empty on all 33 wire runs; paramiko waits 3 s after each injection and sees no DISCONNECT from Dropbear or Go (`disconnect_received` empty in all their 68 runs).
  Timing margin: OpenSSH's UNIMPLEMENTED for UA_PK_OK during a rekey arrives 0.21 s into the 0.35 s window (`kexp_wire.json` `k4_ua`), because the mapper's UA_PK_OK step itself spends about 0.2 s before sending (the same delay as for the normal UA_SUCCESS).
  It was within the window 5/5 in the replay.

## (b) Server logs and source confirm the policy

- **OpenSSH**: two different mechanisms produce the same UNIMPLEMENTED.
  - During a key exchange, transport-range messages (1-49) go to `kex_protocol_error` (`kex.c:236-251`, installed by `kex_reset_dispatch`; after the first KEXINIT `kex_input_kexinit` replaces the KEXINIT handler with `kex_protocol_error`, `kex.c:623`).
    It disconnects only `if ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict)`; otherwise it sends UNIMPLEMENTED.
    This covers K1, K2 and the duplicate KEXINIT of K4 (`kex_protocol_error: type 20 seq 6`).
  - Outside a key exchange, and for non-transport messages, there is simply no handler: `dispatch_protocol_error` (`dispatch.c:39-51`) logs and sends UNIMPLEMENTED.
    This covers K3 and the SR / USERAUTH cases of K4 (`dispatch_protocol_error: type 5 seq 6`, `type 50 seq 6`, no `[preauth]`).
    So OpenSSH does not restrict non-KEX messages during a post-auth rekey at all; it dispatches them normally, and post-auth it has no SERVICE_REQUEST or USERAUTH handler (the same responses as C2/C3 outside a rekey).
- **Dropbear**: deliberate.
  `process-packet.c:90-115`: while `requirenext` is set (30 after KEXINIT, 21 after KEXDH_INIT), an unexpected type 1-49 gets UNIMPLEMENTED, except that SERVICE_REQUEST, SERVICE_ACCEPT and KEXINIT are explicitly excluded and lead to `dropbear_exit("Unexpected packet type %d, expected %d")`.
  Types 50 and up (K4 USERAUTH) also exit.
  That is why C4 (stray NEWKEYS or KEX30 inside the KEX) got UNIMPLEMENTED from Dropbear but K1/K2/K4 do not.
  Outside a KEX: `svr-kex.c:54-55` `Premature kexdh_init message received` and `common-kex.c:122-123` `Unexpected newkeys message` exit.
  `dropbear_exit` closes without a DISCONNECT.
- **Go**: any error in the key exchange or transport layer closes the connection.
  `kex.go:155-164` (expects KEXDH_INIT), `handshake.go:759-762` (expects NEWKEYS), `transport.go:150-157` (NEWKEYS with no pending key change: `got bogus newkeys message`, at any time).
  Pre-auth stray KEX30 fails in `server.go`'s service-request / auth loop (`expected one of [5]` / `[50]`).
  Post-auth our Go server logs nothing (known limit of `remaining_classes.md`); the close is shown by the mapper (`NO_CONN`) and by paramiko (EOF, no DISCONNECT).
  For post-auth KEX30 the mechanism (mux treats it as a channel packet, `invalid channel`) is inferred from source, as for C2/C3.

## (c) Stock paramiko with strict KEX

`kexp_probe.json`, OpenSSH, strict KEX agreed:

- K1 `k1_dupfresh_before30`, `k1_dupfresh_after30`, `k1_dupsame_before30`: `DISCONNECT 2: strict KEX violation: unexpected packet type 20 (seqnr 1)` / `(seqnr 2)`.
- K2 `k2_sr_before30`, `k2_sr_after30`: `DISCONNECT 2: strict KEX violation: unexpected packet type 5 (seqnr 1)` / `(seqnr 2)`.
- K3: unchanged, UNIMPLEMENTED (seq 0/1/2, because strict KEX resets the sequence numbers), and `kex30_*` continue to `exec id`; `KEX_INITIAL` is cleared when the initial KEX ends (`kex.c:563`).
- K4: unchanged, UNIMPLEMENTED (seq 3/4) and the rekey completes, then `exec id`.
- Dropbear and Go close in every K1-K4 mode with strict KEX on or off; Dropbear never sends a DISCONNECT and logs the same `Exit` lines (Dropbear's `first_strict_kex` only matters for the 1-49 UNIMPL branch, which these messages never reach).

So strict KEX turns K1 and K2 into "all three terminate" and leaves K3 and K4 as they are.

Probe artifact, not a finding: with strict KEX, a stray NEWKEYS outside a KEX (`k3_newkeys_*`) is answered with UNIMPLEMENTED, but the connection then dies (`Packet corrupt`, auth fails or `exec id` gets EOF).
OpenSSH resets its read sequence number on every received NEWKEYS when strict (`packet.c:1784-1787`), as draft s3.3 says ("the expected sequence number for packets received from the peer MUST be reset after a SSH_MSG_NEWKEYS is received").
My probe sent a raw NEWKEYS without resetting its own send counter, which the same section requires of the sender, so the desync is on the probe's side.

## (d) RFC adjudication

- RFC 4253 s7.1 (rfc4253.txt lines 1051-1062): "Once a party has sent a SSH_MSG_KEXINIT message for key exchange or re-exchange, until it has sent a SSH_MSG_NEWKEYS message (Section 7.3), it MUST NOT send any messages other than: ... (but SSH_MSG_SERVICE_REQUEST and SSH_MSG_SERVICE_ACCEPT MUST NOT be sent); ... (but further SSH_MSG_KEXINIT messages MUST NOT be sent); ..."
  This constrains the sender only.
  In K1, K2 and K4 the client (the mapper) breaks it; nothing says what the receiver must do.
- s7.1 also says (lines 1071-1077): "The provisions of Section 11 apply to unrecognized messages" and "during a key re-exchange, after sending a SSH_MSG_KEXINIT message, each party MUST be prepared to process an arbitrary number of messages that may be in-flight before receiving a SSH_MSG_KEXINIT message from the other party."
  Neither binds the servers here.
  KEXINIT (20), SERVICE_REQUEST (5), NEWKEYS (21), KEXDH_INIT (30) and USERAUTH_REQUEST (50) are recognised message numbers, so s11.4's "MUST respond to all unrecognized messages with an SSH_MSG_UNIMPLEMENTED" does not require OpenSSH's answer or forbid the others' close.
  The in-flight clause does not cover K4: the client started the rekey, so the server had already received the client's KEXINIT when the SR or USERAUTH arrived, and these messages cannot be "in flight before receiving a SSH_MSG_KEXINIT from the other party".
- K3: no KEX is in progress, so s7.1 does not apply.
  s7.3 "When this message is received, the new keys and algorithms MUST be used for receiving" presupposes a key exchange that produced new keys; for a NEWKEYS with none, and for a KEXDH_INIT outside a KEX, RFC 4253 is silent.
- s11.1: implementations "SHOULD be able to send" DISCONNECT is a capability, not a per-event duty; closing without DISCONNECT is poor practice but violates no requirement.
- draft-ietf-sshm-strict-kex-01 s3.2: "When strict KEX is enabled, implementations MUST terminate the connection if they receive a non-KEX message during the initial key exchange" and "any message permitted during KEX can be only accepted the expected number of times".
  This makes K2 (non-KEX message) and K1 (second KEXINIT) terminations mandatory, but only in the initial KEX and only when strict KEX is negotiated.
  All three servers comply when it is.
  It says nothing about messages outside the initial KEX, so K3 and K4 stay unspecified under strict KEX too.

Conclusion: every claim is an unspecified divergence of receiver policy.
OpenSSH is lenient (UNIMPLEMENTED, carry on) wherever strict KEX does not force it to terminate; Dropbear and Go terminate without DISCONNECT.
For K1 and K2 the only applicable MUST is the strict-KEX one, which the mapper never triggers.
No server violates RFC 4253 here; the mapper (as client) does, by design of the test.

## What I changed or might have broken

- Nothing under `vendor/`, `psm/`, `suts/`, `tests/` was changed; no commits.
- New files: `scratch/review/kexp_probe.py`, `scratch/review/kexp_wire.py`, and `results/review/kexp_probe.json`, `kexp_probe.log`, `kexp_wire.json`, `kexp_wire.log`, `kexp_source_excerpts.txt`, `kex_phase.md`.
- Box usage: at most 2 concurrent jobs (the probe and one throwaway `docker run --rm` of `psm-mapper:pinned`, as in the earlier review); about 135 connections to the servers behind mappers 8001-8003; the mapper containers themselves were not used or restarted.
  My first launch of the wire job failed before starting (wrong working directory in the second background command) and was rerun; nothing else ran.

## Limits

- The paramiko probe ran 1 rep per mode and strict setting; determinism rests on the mapper replay (5/5 on all three servers) plus agreement between the two clients.
- Go's post-auth closes (K3 after auth, K4) are not logged by our Go server; their cause is from source plus the observed EOF.
- One configuration per server; only DH group14 (mapper) and ML-KEM768x25519 (paramiko) KEX methods were exercised.
