# Skeptical review of the remaining disagreement classes C1-C5

Reviewer, 2026-11-07, about 14:05-14:45 (box time).
Starting position: every class is a harness artifact until each artifact hypothesis is refuted with evidence.
Claims under review: the 13 Dropbear-vs-Go A-diff sequences replayed on all three servers (`results/replay/A_dropbear_vs_gossh_replay.json`, JOURNAL 14:00).
Earlier reviews (`ua_without_sr.md`, `ch_open_preauth.md`) already established that the mapper's UA_PK_OK, SR_AUTH, CH_OPEN and DEBUG bytes are correct, that P5 is sound, and that Go and Dropbear close without SSH_MSG_DISCONNECT; that is not redone here.

## Verdicts

| Class | Verdict | OpenSSH 10.0p1 | Dropbear 2025.88 | Go x/crypto/ssh 0.58.0 | RFC adjudication |
| --- | --- | --- | --- | --- | --- |
| C1 rekey before auth | REAL | ignores KEXINIT, answers UNIMPLEMENTED, never sends its KEXINIT | completes the rekey | completes the rekey | OpenSSH violates the letter of the MUST in RFC 4253 s9; Dropbear and Go comply |
| C2 USERAUTH_REQUEST after success | REAL | UNIMPLEMENTED, session stays usable | silently ignored | TCP close, no DISCONNECT | RFC 4252 s5.1/s5.3 SHOULD: Dropbear complies; OpenSSH and Go deviate from the SHOULD (Go more severely) |
| C3 repeated SERVICE_REQUEST ssh-userauth | REAL | pre-auth: SERVICE_ACCEPT; post-auth: UNIMPLEMENTED | SERVICE_ACCEPT in both states | TCP close in both states | No clause addresses a repeated request; under a literal per-request reading of RFC 4253 s10, OpenSSH's post-auth UNIMPLEMENTED is neither "accept" nor "disconnect" |
| C4 errors inside KEX | REAL (legacy, non-strict branch) | UNIMPLEMENTED, KEX can still complete | UNIMPLEMENTED, KEX can still complete | TCP close | Not specified by RFC 4253 (divergence). With strict KEX all three terminate on the initial-KEX cases (draft MUST met); the rekey case stays UNIMPL vs close |
| C5 KEX30 or NEWKEYS before the client's KEXINIT | REAL (legacy branch); two harness quirks in how the mapper shows it | UNIMPLEMENTED for seq 0, then normal KEX | UNIMPLEMENTED for seq 0, then normal KEX | TCP close | Not specified by RFC 4253 (divergence). With strict KEX all three terminate (draft MUST met) |

Every result below is deterministic: 27 new mapper sequences x 5 reps x 3 servers (`rc_replay.json`, all 81 entries `deterministic: true`), and 14 probe modes x strict KEX {off, on} x 2 reps x 3 servers (`rc_probe.json`, all reps agree on the server's answer; they differ only in the order in which unrelated packets arrive).
All files are under `results/review/` unless a path is given.

## Tools

- `scratch/review/rc_probe.py` -> `rc_probe.json`: stock paramiko 5.1.0, i.e. an independent client.
  Each connection uses fresh random KEXINIT cookies and ML-KEM768x25519 KEX instead of the mapper's DH group14.
  Every mode runs with strict KEX advertised and with it not advertised.
  A packet-level read/send hook is installed before the handshake.
  It logs incoming UNIMPLEMENTED packets with their rejected sequence number and then hides them from paramiko, so paramiko's own state machine is not disturbed.
  The probe watches for 3 s after each injected message (the mapper reads for 0.35 s).
  Where the connection survives, it then authenticates and runs `exec id` on the same connection.
- `scratch/review/rc_wire.py` -> `rc_wire.json`: the vendored mapper library, unchanged, in a throwaway `psm-mapper:pinned` container (same timing profile as the mappers).
  It records, for each abstract step, every packet sent (type, outgoing seq, encrypted or not, KEXINIT payload) and every packet received (type, UNIMPL's rejected seq).
  After the last step it does an extra 2 s read.
- `scratch/review/rc_seqs.json` -> `rc_replay.json`: mapper replay through `psm.replay`, with the server log windows.
  The sequences add timing pads (`DEBUG DEBUG`), continuation checks (does auth still work afterwards?) and variants.
- `rc_source_excerpts.txt`: the server source lines cited below (openssh-portable V_10_0_P1, dropbear DROPBEAR_2025.88, golang/crypto v0.58.0).

## Generic artifact hypotheses (all classes)

- **G1: the 0.35 s output window misses a late DISCONNECT or close.** Refuted.
  `rc_wire.json`: for every class, on every server, the extra 2 s read after the last step receives nothing.
  `rc_replay.json`: on OpenSSH and Dropbear, every disputed step followed by `DEBUG DEBUG` gives `NO_RESP NO_RESP`, i.e. the connection is still open with nothing pending.
  `rc_probe.json`: stock paramiko waits 3 s and never sees a DISCONNECT in the non-strict modes; the connection is still active and `exec id` works.
- **G2: the NO_CONN-after-first-message rule hides a close.**
  `read_multiple_responses` drops NO_CONN once another message has been read in the same step.
  This hides a close in exactly one place: Go in C5 (`KEX30` -> `KEXINIT`; the close shows up at the next step as `NO_CONN`, see C5).
  The rule cannot hide anything behind OpenSSH's or Dropbear's UNIMPL, because later steps on the same connection succeed (auth, `CH_OPEN_SUCCESS`, `exec id`).
- **G3: rate limits or connection limits.** Refuted.
  OpenSSH runs with `PerSourcePenalties no` and `MaxStartups 100:30:200` (`suts/openssh/sshd_config`).
  Dropbear's `MAX_UNAUTH_PER_IP 5` would show up as an immediate drop at step 1 (`NO_CONN` or a paramiko connect error).
  That never happened in 405 mapper queries or 168 probe connections, even though the learners shared the same servers.
- **G4: a mapper crash or undecodable packet.** Refuted.
  RestartCount stays 0 on `psm-mapper-openssh`, `psm-mapper-dropbear` and `psm-mapper-gossh`, and none of them has `~/self-impl-errorlog.txt`.
  The 30 `Newkeys sent, but cannot proceed` lines in the OpenSSH mapper's log are the mapper's own caught exception for NEWKEYS without a fresh key exchange (side finding 2), not a crash.

## C1: rekey before authentication

Claim: `KEXINIT KEX30 NEWKEYS KEXINIT` and `... SR_AUTH KEXINIT`: OpenSSH `UNIMPL`; Dropbear and Go `KEXINIT`, and the rekey completes. After auth, all three accept a rekey.

- **H1.1: P4 (one cookie per connection) makes the pre-auth KEXINIT look like a replay.** Refuted on three counts.
  - Wire: the mapper's rekey KEXINIT is byte-identical to its initial KEXINIT, cookie included, both before auth and after auth.
    With the cookie masked, the pre-auth and post-auth rekey KEXINITs are identical to each other on all three servers (`rc_wire.json` `kexinit_comparison`: `rekey_identical_to_initial_incl_cookie: true` for c1_pre_nosr, c1_pre_sr, c1_post; `pre_vs_post_rekey_identical_except_cookie: true`).
    OpenSSH accepts these exact bytes after auth (`c1_post`: server KEXINIT in 2 ms; `rc_replay.json` `... UA_PK_OK KEXINIT KEX30 NEWKEYS CH_OPEN` -> `KEXINIT KEX31+NEWKEYS NO_RESP CH_OPEN_SUCCESS`, 5/5).
  - Independent client: stock paramiko, which draws a fresh cookie for every KEXINIT, gets the same answer.
    Before any service request (`rekey_preauth`) and after SERVICE_ACCEPT (`rekey_after_sr`), OpenSSH answers `UNIMPLEMENTED` with the right sequence number and never sends KEXINIT within 4 s.
    The rejected seq is 3 or 4 without strict KEX and 0 or 1 with it, because strict KEX resets the sequence numbers.
    The post-auth control (`rekey_postauth`) completes on OpenSSH (`20 31 21`, then `exec id`).
    Dropbear and Go complete the pre-auth rekey (`20 31 21`), then authenticate, then `exec id` returns `uid=1000(tester)` / `hello from gossh`, with strict KEX on or off (`rc_probe.json`).
  - Source: in the pre-auth process the KEXINIT payload is never parsed (below), so its cookie cannot matter.
- **H1.2: OpenSSH half-processes the KEXINIT and the connection is broken afterwards.** Refuted.
  Mapper: `KEXINIT KEX30 NEWKEYS KEXINIT SR_AUTH UA_PK_OK` -> `UNIMPL SR_ACCEPT UA_SUCCESS+GLOBAL_REQUEST` (5/5).
  Paramiko: after the refused rekey (paramiko's local KEX state is reset), publickey auth and `exec id` succeed on the same connection (`rc_probe.json`, all 8 OpenSSH `rekey_preauth`/`rekey_after_sr` runs).
  Also refuted after a failed auth: `... SR_AUTH UA_PK_NOK KEXINIT DEBUG` -> `UNIMPL NO_RESP` on OpenSSH, `KEXINIT NO_RESP` on the others.
- **H1.3: the server's KEXINIT just arrives late.** Refuted: nothing arrives in the 2 s late read, in `DEBUG DEBUG` pads, or in paramiko's 4 s wait (G1).
- **Server log:** the KEXINIT is dispatched to the default handler in the pre-auth process.
  `dispatch_protocol_error: type 20 seq 3 [preauth]` (no SR) and `type 20 seq 4 [preauth]` (after SR) appear in the replay and probe windows, followed by `send packet: type 3`, and `type 20 seq 0 [preauth]` for strict-KEX paramiko.
- **Source, OpenSSH (V_10_0_P1):**
  - `auth2.c:175` `do_authentication2()` calls `ssh_dispatch_init(ssh, &dispatch_protocol_error)`, which overwrites the whole dispatch table, including the `SSH2_MSG_KEXINIT -> kex_input_kexinit` entry that `kex.c:534` `kex_input_newkeys()` had just installed.
    It then re-adds only SERVICE_REQUEST (and EXT_INFO).
  - `serverloop.c:895-896` (post-auth process) explicitly re-installs `/* rekeying */ ssh_dispatch_set(ssh, SSH2_MSG_KEXINIT, &kex_input_kexinit)`.
  - `packet.c:1055` `/* XXX client can't cope with rekeying pre-auth */` stops the server from starting a rekey before auth.
  So pre-auth rekeying is deliberately unsupported in both directions; the design reason in the source is client compatibility, plus the privsep hand-off of the key state from `sshd-auth` to `sshd-session` (`sshd-auth.c:791-797`).
- **Source, Dropbear:** `svr-session.c:55` registers `recv_msg_kexinit` unconditionally, and `process-packet.c` lets types up to 60 through before auth.
  **Source, Go:** `handshake.go` `readOnePacket` handles `msgKexInit` at any time after the first one.
- **Prior work:** this is SPIN 2017's OpenSSH 6.9p1 property-5 violation ("Rekey Fail Before Auth", also NDSS 2023 on 8.8p1, notes/literature.md item 1), still present in 10.0p1.

RFC adjudication: RFC 4253 s9 "When this message is received, a party MUST respond with its own SSH_MSG_KEXINIT message, except when the received SSH_MSG_KEXINIT already was a reply."
The section states no exception for the authentication phase, and the received KEXINIT here is not a reply (the server had none outstanding).
So OpenSSH violates the letter of this MUST before authentication; Dropbear and Go comply.
Practical effect: a client that rekeys before auth gets stuck, because RFC 4253 s7.1 forbids it from sending non-KEX messages until its NEWKEYS.
For example, stock paramiko's `Transport.renegotiate_keys()` has no timeout and returns only on completion or a dead connection, so pre-auth on OpenSSH it would block until the server drops the connection (inferred from the paramiko source; the probe used a 4 s wait instead).
No security impact found: the KEXINIT is not parsed, and normal auth works afterwards.

## C2: USERAUTH_REQUEST after USERAUTH_SUCCESS

Claim: `... SR_AUTH UA_PK_OK UA_PK_OK`: OpenSSH `UNIMPL`, Dropbear `NO_RESP`, Go `NO_CONN`.

- **H2.1: specific to the mapper's publickey request.** Refuted.
  Mapper with UA_PK_OK, UA_PW_OK, UA_NONE, UA_PK_NOK after success, and UA_PK_OK after a password login: OpenSSH `UNIMPL`, Dropbear `NO_RESP`, Go `NO_CONN` in every case (`rc_replay.json`, 5/5 each).
  Paramiko `ua2_publickey` (signed by stock AuthHandler), `ua2_password` and `ua2_none`, with strict KEX on and off, give the same outcomes:
  - OpenSSH: `3(unimpl seq 5)` (seq 2 with strict KEX), then `exec id` works.
  - Dropbear: nothing within 3 s, then `exec id` works.
  - Go: connection closed, no packet received, no DISCONNECT.
- **H2.2: Dropbear's NO_RESP is a late reply.** Refuted.
  `UA_PK_OK UA_PK_OK DEBUG DEBUG` -> `NO_RESP NO_RESP NO_RESP`; the 2 s late read is empty; paramiko's 3-s watch is empty, and `UA_PK_OK UA_PK_OK CH_OPEN` -> `NO_RESP CH_OPEN_SUCCESS`.
  Source: `svr-auth.c:85` `if (ses.authstate.authdone == 1) { TRACE(("... authdone already")); return; }`.
- **H2.3: OpenSSH's UNIMPL is a race with the post-auth GLOBAL_REQUEST.** Refuted.
  The UNIMPL names the request's own sequence number (5, or 2 with strict KEX).
  The log line is `dispatch_protocol_error: type 50 seq 5` without `[preauth]`, i.e. from the post-auth process, which installs no USERAUTH handler (`serverloop.c:879` default `dispatch_protocol_error`).
  Detail: `auth2.c:432-434` switches USERAUTH_REQUEST to the silent `dispatch_protocol_ignore` on success, but only in the pre-auth process.
  That process stops reading right after sending SUCCESS (the `authctxt->success` done-flag), so the ignore handler never runs.
  Even two requests sent back to back (`ua_pipelined`) give SUCCESS and then `UNIMPLEMENTED seq 5`; `dispatch_protocol_ignore` occurs 0 times in all probe log windows.
  OpenSSH's code intends to ignore silently, but the privsep hand-off defeats it.
- **H2.4: Go's NO_CONN is a mapper decode failure.** Refuted: paramiko sees the same close (EOF, no DISCONNECT).
  Source: `mux.go:254-277` treats any message that is not a channel open, global request or ping as a channel message.
  It reads bytes 1-4 (here the username length, 6) as a channel id, `handleUnknownChannelPacket` returns `ssh: invalid channel 6` (`mux.go:387`), and the mux loop closes the connection.
  Our Go server does not log mux errors, so the server log shows only `connection closed`.

RFC adjudication: RFC 4252 s5.1 "When SSH_MSG_USERAUTH_SUCCESS has been sent, any further authentication requests received after that SHOULD be silently ignored" (and s5.3).
Dropbear complies.
OpenSSH deviates from the SHOULD: UNIMPLEMENTED is not silence, though it is harmless (SPIN 2017 property 11, NDSS 2023 "Unignored Auth Request After USERAUTH_SUCCESS").
Go deviates from the SHOULD more severely: it tears down an authenticated session.
No MUST is involved.

## C3: repeated SERVICE_REQUEST "ssh-userauth"

Claim: `SR_AUTH SR_AUTH` (pre-auth): OpenSSH and Dropbear `SR_ACCEPT`, Go `NO_CONN`. `UA_PK_OK SR_AUTH` (post-auth): OpenSSH `UNIMPL`, Dropbear `SR_ACCEPT`, Go `NO_CONN`.

- **H3.1: mapper-specific.** Refuted.
  Paramiko `sr_twice` gives `6 6` on OpenSSH and Dropbear; Go closes after the first accept, with log `ssh: unexpected message type 5 (expected one of [50])`.
  Paramiko `sr_after_auth` gives OpenSSH `3(unimpl seq 5)` (seq 2 with strict KEX), Dropbear `6`, Go close.
  Strict KEX on or off makes no difference.
- **H3.2: the state is damaged afterwards.** Refuted.
  `SR_AUTH SR_AUTH UA_PK_OK` -> `UA_SUCCESS` on OpenSSH and Dropbear.
  A third SR is accepted again, and SR after a failed auth is accepted (`UA_PK_NOK SR_AUTH` -> `SR_ACCEPT` on OpenSSH and Dropbear, `NO_CONN` on Go).
  `UA_PK_OK SR_AUTH CH_OPEN` -> `CH_OPEN_SUCCESS` on OpenSSH and Dropbear.
  Paramiko runs `exec id` after both modes.
  Late output: `SR_AUTH DEBUG DEBUG` after auth -> `NO_RESP NO_RESP`.
- **Source:**
  - OpenSSH: `auth2.c` `input_service_request` stays installed pre-auth and accepts `ssh-userauth` whenever `!authctxt->success`.
    The post-auth process has no SERVICE_REQUEST handler, so `dispatch_protocol_error: type 5 seq 5` (no `[preauth]`) answers UNIMPLEMENTED.
  - Dropbear: `svr-service.c:47-54` accepts `ssh-userauth` unconditionally, in any auth state.
  - Go: `server.go:425-445` reads exactly one service request.
    In the auth loop a second one fails `Unmarshal` (`expected one of [50]`); after auth the mux treats it as a channel packet (`invalid channel 12`, the length of "ssh-userauth").

RFC adjudication: no clause addresses a second request for the same service, or a request for ssh-userauth after authentication.
RFC 4253 s10 says: "If the server rejects the service request, it SHOULD send an appropriate SSH_MSG_DISCONNECT message and MUST disconnect. If the server supports the service (and permits the client to use it), it MUST respond with" SERVICE_ACCEPT.
Read per request, this allows only "accept" or "disconnect".
- Dropbear (accept everywhere) and OpenSSH pre-auth (accept) satisfy it.
- Go satisfies the MUST (it disconnects) but skips the SHOULD DISCONNECT message.
- OpenSSH post-auth's UNIMPLEMENTED is neither.
  This is SPIN 2017 property 8 "violated*" and NDSS 2023 "Invalid SERVICE_REQUEST_USERAUTH Response".
Because s10 is written for the single service request that follows key exchange, I label C3 an unspecified divergence.
Under the per-request reading, OpenSSH post-auth breaks the accept-or-disconnect rule and Go misses the SHOULD.
No security impact: OpenSSH changes no state, and Dropbear's re-accept leads nowhere, because later USERAUTH requests are ignored (C2).

## C4: protocol errors inside the key exchange

Claim: `KEXINIT NEWKEYS`, `KEXINIT KEX30 KEX30`, and the post-auth rekey `KEXINIT NEWKEYS`: OpenSSH and Dropbear `UNIMPL`, Go `NO_CONN`.

- **H4.1: UNIMPL is an artifact of the mapper not negotiating strict KEX.** This is the important qualification, and it is half true.
  Stock paramiko, initial KEX:
  - Not strict: OpenSSH and Dropbear answer UNIMPLEMENTED (`kex_newkeys_first`: `3(unimpl seq 1)`; `kex_dup_init`: KEX31, NEWKEYS, EXT_INFO, then `3(unimpl seq 2)`).
    In the duplicate case the KEX completes and `exec id` works.
  - Strict (`kex-strict-c-v00@openssh.com` agreed):
    - OpenSSH sends `DISCONNECT 2: strict KEX violation: unexpected packet type 21 (seqnr 1)` / `... type 30 (seqnr 2)` (`kex.c:241-243`).
    - Dropbear closes without a DISCONNECT, log `Exit before auth: Unexpected packet type 21, expected 30` / `Unexpected packet type 30, expected 21` (`process-packet.c:100-115`, with `first_strict_kex`).
    - Go closes in both modes (`got bogus newkeys message`, `unexpected message type 30 (expected 21)`).
  Rekey (`rekey_newkeys_no_kexdh`): UNIMPLEMENTED on OpenSSH (`dispatch_protocol_error: type 21`) and Dropbear even with strict KEX, because the draft's restrictions cover only the initial KEX (`KEX_INITIAL`, `!recvfirstnewkeys`); Go closes.
  So for the initial-KEX cases the UNIMPL is the legacy, non-strict behaviour, and with strict KEX all three servers terminate.
  The mapper's models describe only the non-strict branch, which real clients that offer strict KEX (current OpenSSH, paramiko >= 3.4) no longer hit.
  The rekey case is a disagreement under both settings.
- **H4.2: the mapper's KEX bytes are wrong.** Refuted.
  The wire view shows the mapper sends exactly one NEWKEYS (seq 1, plaintext), or a second KEX30 (seq 2, plaintext), and each UNIMPL names that seq.
  The continuation `KEXINIT NEWKEYS KEX30 NEWKEYS SR_AUTH UA_PK_OK` and `KEXINIT KEX30 KEX30 NEWKEYS SR_AUTH UA_PK_OK` end in `UA_SUCCESS` on OpenSSH and Dropbear (5/5).
  So the stray message was simply ignored, and the paramiko non-strict runs agree.
- **H4.3: late DISCONNECT.** Refuted: `DEBUG DEBUG` pads give `NO_RESP NO_RESP` on OpenSSH and Dropbear, and the 2-s and 3-s watches see nothing.
- **Source:**
  - OpenSSH `kex.c:236-251` `kex_protocol_error`: disconnect only if `KEX_INITIAL && kex_strict`, otherwise UNIMPLEMENTED.
  - Dropbear `ses.requirenext` (30 after KEXINIT, 21 after KEXDH_INIT, `svr-kex.c:104`): an unexpected type in 1-49 gets `recv_unimplemented()` unless `first_strict_kex`.
  - Go `handshake.go:755-762` and `transport.go:157` return an error, which closes the connection.

RFC adjudication: RFC 4253 s7.1/s7.3 restrict what a party sends, not how it must react to a received out-of-order NEWKEYS or KEXDH_INIT.
s11.4 (UNIMPLEMENTED) covers unrecognised message numbers, and 21 and 30 are recognised.
So without strict KEX this is an unspecified divergence: OpenSSH and Dropbear are lenient, and Go aborts with no DISCONNECT (the RFC 4253 s11.1 "SHOULD be able to send").
With strict KEX (draft-ietf-sshm-strict-kex: "MUST terminate the connection if they receive a non-KEX message during the initial key exchange", and each KEX message is accepted once), all three comply in the initial KEX; only OpenSSH sends a DISCONNECT.

## C5: KEX30 or NEWKEYS before the client's KEXINIT

Claim: first input `KEX30` or `NEWKEYS`: OpenSSH and Dropbear `KEXINIT+UNIMPL`, Go `KEXINIT` then closed.

- **H5.1: harness quirk A, the abstract step is two wire packets.** Confirmed as a quirk, but it does not change the verdict.
  `rc_wire.json` c5_*: the step `KEX30` sends `30` (seq 0) and then, on reading the server's KEXINIT, an automatic client KEXINIT (seq 1).
  The source is `transport.py:2827-2829` `_negotiate_keys`: `if self.local_kex_init is None: self._send_kex_init()` (upstream behaviour, not one of our patches).
  The servers' reactions are to the seq-0 packet: OpenSSH logs `kex_protocol_error: type 30 seq 0` / `type 21 seq 0`, and both OpenSSH and Dropbear send `UNIMPLEMENTED seq 0`.
  Go logs `first packet should be msgKexInit` / `got bogus newkeys message`.
  Consequence for the models: the mapper always ends up having sent a KEXINIT, so `KEX30 KEX30 ... UA_PK_OK` succeeds on OpenSSH and Dropbear.
  Our models cannot tell whether a server would start a KEX without any client KEXINIT (literature item 2).
- **H5.2: harness quirk B, Go's close is hidden.** Confirmed: Go's `KEXINIT` output hides the close in the same step (G2); it shows up at the next step (`KEX30 DEBUG DEBUG` -> `KEXINIT NO_CONN NO_CONN`), and paramiko sees EOF right after the server KEXINIT.
  The disagreement (UNIMPL and continue vs close) is real; only its presentation is mapper-shaped.
- **H5.3: UNIMPL is the non-strict branch.** Confirmed with stock paramiko, which sends the stray message as the very first packet:
  - Not strict: OpenSSH and Dropbear send `UNIMPLEMENTED seq 0`, complete the KEX, authenticate and run `exec id`.
  - Strict: OpenSSH sends `UNIMPLEMENTED seq 0` (strictness is unknown until the client's KEXINIT arrives) and then `DISCONNECT 2: strict KEX violation: KEXINIT was not the first packet` (`kex.c:962-967`).
    Dropbear exits with `First packet wasn't kexinit` and no DISCONNECT (`common-kex.c:572-573`).
  - Go closes in both modes.

RFC adjudication: RFC 4253 s7.1 says key exchange begins with each side sending KEXINIT, but gives no rule for a server that receives something else first.
So without strict KEX this is an unspecified divergence (the "liberal start" seen since OpenSSH 6.9).
With strict KEX ("MUST verify that the SSH_MSG_KEXINIT was the first message received from the peer") all three comply; only OpenSSH sends a DISCONNECT.

## Side findings for the harness

1. **Automatic KEXINIT (C5 quirk A).** Any first input other than KEXINIT also puts a client KEXINIT on the wire, as soon as the mapper reads the server's KEXINIT.
   Transitions from the initial state on non-KEXINIT inputs must be described as "X, then the mapper's KEXINIT".
2. **NEWKEYS without a fresh key exchange corrupts the mapper's outbound stream.** `_activate_outbound` re-derives keys from the old K/H (`transport.py:3223-3256`) and re-initialises AES-CTR, which resets the counter, while the server keeps its old cipher state.
   Every input after such a NEWKEYS is garbage to the server.
   This happens after a post-auth `KEXINIT NEWKEYS`, and after OpenSSH has ignored a pre-auth rekey (`KEXINIT KEX30 NEWKEYS`).
   Evidence:
   - `rc_wire.json` c4_rekey_newkeys: `DEBUG` -> `NO_CONN` on OpenSSH and Dropbear.
   - `rc_replay.json` `... SR_AUTH KEXINIT KEX30 NEWKEYS UA_PK_OK` -> OpenSSH `UNIMPL UNIMPL UNIMPL NO_CONN`, with OpenSSH log `Bad packet length 4066349024` / `Packet corrupt` / `message authentication code incorrect`.
   - The `Integrity error (bad packet size ...)` lines in Dropbear's log windows during learning.
   Before the first key exchange K is unset, the mapper's exception is caught, and nothing changes, so `KEXINIT NEWKEYS ...` pre-KEX is unaffected.
   The NEWKEYS step's own output is correct; everything after it in such a run is a mapper artifact.
   Do not report any model difference that lies beyond such a NEWKEYS, for example OpenSSH's `NO_CONN` after a refused pre-auth rekey.
3. **No strict KEX in the mapper.** C4 and C5 describe the legacy branch; with strict KEX, the initial-KEX parts of C4 and all of C5 become "all three terminate".
   The report should say so instead of presenting them as current-client behaviour.

## Limits

- One configuration per server; LoginGraceTime and MaxAuthTries were not varied.
- The servers were shared with running learners (B_openssh, A_openssh, B_dropbear, B_gossh) and with my own replay.
  Log windows contain their lines, so log claims rely on lines whose sequence numbers and contents match our inputs (e.g. `type 20 seq 3 [preauth]`, strict-KEX `seq 0`).
- Go logs nothing for post-auth mux errors in our test server; the Go explanation for C2 and C3 post-auth rests on source plus the observed EOF.
- Paramiko's `rekey_newkeys_no_kexdh` leaves the session mid-KEX, so no `exec id` was attempted there.
- The C1 "client blocks" consequence for paramiko is inferred from paramiko's `renegotiate_keys` source, not run to LoginGraceTime.

## Files

- `results/review/rc_replay.json`: 27 sequences x 5 reps x 3 servers, with server logs (sequences in `scratch/review/rc_seqs.json`).
- `results/review/rc_probe.json`: stock paramiko 5.1.0, 14 modes x strict {off, on} x 2 reps x 3 servers, packet-level wire, paramiko log, server log.
- `results/review/rc_wire.json`: mapper wire view per step, KEXINIT byte comparison, 2 s late read.
- `results/review/rc_source_excerpts.txt`: cited server source lines.
- Scripts: `scratch/review/rc_probe.py`, `scratch/review/rc_wire.py`, `scratch/review/rc_seqs.json`.
