# Skeptical review of E1/E2: SERVICE_REQUEST "ssh-connection"

Reviewer, 2026-11-07, about 14:45-15:05 (box time).
Starting position: each disagreement is a harness artifact until every artifact hypothesis is refuted with evidence.
Claims under review: rows 1, 3, 7 and 8 of `results/final/verified_B_only.md` (`results/replay/B_only_replay.json`).
Earlier reviews (`ua_without_sr.md`, `ch_open_preauth.md`, `remaining_classes.md`) already established that the mapper's SR_AUTH, UA_*, CH_OPEN and DEBUG bytes are correct, that the mapper's read window does not miss late packets (G1), and that Dropbear and Go never send SSH_MSG_DISCONNECT on their error paths.
That is not redone here.

## Verdicts

| Claim | OpenSSH 10.0p1 | Dropbear 2025.88 | Go x/crypto/ssh 0.58.0 | RFC adjudication |
| --- | --- | --- | --- | --- |
| E1 SR "ssh-connection" before auth (directly after KEX, after SR_AUTH, after a failed UA) | REAL: DISCONNECT code 2 "bad service request ssh-connection", then close | REAL: TCP close in <= 2 ms, no packet at all (no DISCONNECT) | REAL: TCP close in <= 2 ms, no packet at all (no DISCONNECT) | RFC 4253 s10: all three reject and disconnect (MUST met). Only OpenSSH sends the DISCONNECT (SHOULD); Dropbear and Go miss the SHOULD. |
| E2 SR "ssh-connection" after successful auth | REAL: UNIMPLEMENTED naming the request's own seq; session stays usable | REAL: SERVICE_ACCEPT "ssh-connection"; no state change, session stays usable | REAL: TCP close, no DISCONNECT, authenticated session lost | Unspecified (RFC 4253 s10 covers the one request after KEX; RFC 4252 s5 starts ssh-connection through the USERAUTH service field). Per-request reading: Dropbear accepts (fine), Go disconnects without the SHOULD message, OpenSSH's UNIMPLEMENTED is neither accept nor disconnect. |

Both are real and deterministic, but neither is an independent new finding:
E1 is one more instance of "Dropbear and Go close silently, OpenSSH sends DISCONNECT" (same as D2 and C2-C5);
E2 has exactly the outcomes and the same source lines as C3's post-auth SR_AUTH (`remaining_classes.md`), so it should be merged into C3 rather than counted separately.

Determinism: 11 mapper sequences x 5 reps x 3 servers, all 33 entries `deterministic: true` (`srconn_replay.json`).
Stock paramiko: 5 modes x strict KEX {off, on} x 2 reps x 3 servers = 60 connections, all reps agree (`srconn_probe.json`).
All files are under `results/review/` unless a path is given.

## Tools

- `scratch/review/srconn_seqs.json` -> `srconn_replay.json`: mapper replay via `psm.replay` on 8001/8002/8003 with server-log windows.
  Adds timing pads (`DEBUG DEBUG`), continuations (`CH_OPEN`, a second `SR_CONN`, `UA_PK_OK`), a post-auth rekey before `SR_CONN`, and SR_CONN after a failed UA (`UA_PK_NOK`, `UA_NONE`).
- `scratch/review/srconn_probe.py` -> `srconn_probe.json`: stock paramiko 5.1.0, reusing `rc_probe.py`'s packet instrumentation (every packet logged with type and seq, UNIMPLEMENTED's rejected seq, DISCONNECT code and text).
  Fresh cookies, ML-KEM768x25519 KEX, strict KEX advertised and not.
  The SERVICE_REQUEST is a paramiko `Message` sent with `transport._send_message`; no hand-written crypto.
  3 s watch after the injection; where the connection survives, `exec id` on the same connection.
  Modes: `srconn_preauth`, `srconn_after_sr`, `srbogus_preauth` (control: "bogus-service@example.com"), `srconn_postauth`, `srconn_postauth_chan` (exec id on channel 0 first, then SR, then exec id again).
  After auth, paramiko's `_parse_service_accept` is replaced by a recorder, so an accept cannot trigger a further USERAUTH_REQUEST; the wire log confirms no outgoing type 50 after the injection.
- `srconn_source_excerpts.txt`: the cited server source (openssh-portable V_10_0_P1, dropbear DROPBEAR_2025.88, golang/crypto v0.58.0).
- The mapper's SR_CONN builder (`vendor/ssh-fuzzer/ssh-mapper/manualparamiko/transport.py:2173`) sends `byte 5, string "ssh-connection"`, nothing else.

## E1: SERVICE_REQUEST "ssh-connection" before authentication

Claim: `KEXINIT KEX30 NEWKEYS SR_CONN` and `... SR_AUTH SR_CONN`: OpenSSH `DISCONNECT`; Dropbear and Go `NO_CONN`.

- **H1.1: Dropbear/Go send a DISCONNECT that the mapper loses (0.35 s window, or the rule that drops NO_CONN after another message in the same step).** Refuted.
  - Stock paramiko, which logs every decrypted packet until EOF and waits 3 s: on Dropbear and Go, in all 24 pre-auth runs (`srconn_preauth`, `srconn_after_sr`, `srbogus_preauth`, strict on/off), zero packets arrive after the SERVICE_REQUEST, `disconnect_received` is empty, and paramiko logs only `EOF in transport thread`, 0-2 ms after the send.
    OpenSSH in the same modes: `Disconnect (code 2): bad service request ssh-connection`, 0-2 ms after the send (8/8).
  - The mapper's NO_CONN-dropping rule only removes a NO_CONN after a message was read; it cannot hide a DISCONNECT, and on Dropbear/Go there is no message to read.
  - Mapper with pads: `SR_CONN DEBUG DEBUG` -> `NO_CONN NO_CONN NO_CONN` on Dropbear and Go and `DISCONNECT NO_CONN NO_CONN` on OpenSSH (5/5): nothing late, the connection is gone.
  - Source: neither server has a send path for DISCONNECT here (below); Dropbear's `UNAUTH_CLOSE_DELAY` defaults to 0, consistent with the observed <= 2 ms close.
- **H1.2: the mapper's SR_CONN bytes are malformed, so the servers close for a parse error.** Refuted.
  Server logs name the service: Dropbear `Exit before auth from <...>: Request for connection before auth` (the ssh-connection branch, not `Unrecognised SSH_MSG_SERVICE_REQUEST`, which the bogus control produces); Go `handshake error ...: ssh: requested service 'ssh-connection' before authenticating`; OpenSSH `Disconnecting ...: bad service request ssh-connection [preauth]` (`B_only_replay.json`, `srconn_replay.json`).
  The same mapper bytes are accepted by Dropbear after auth (E2), and stock paramiko's independently built request gets identical answers.
- **H1.3: specific to "directly after KEX" or to the mapper's state.** Refuted.
  After SR_AUTH, after `UA_PK_NOK` and after `UA_NONE`, the outcome is the same on all three servers (`srconn_replay.json`, 5/5 each), and strict KEX on/off makes no difference in the probe.
- **Mechanism nuance (Go, after SR_AUTH):** Go's close there is not about "ssh-connection" at all.
  Go reads exactly one SERVICE_REQUEST; a second one of any name fails in the auth loop with `ssh: unexpected message type 5 (expected one of [50])` (server log, mapper and probe), the C3 mechanism.
  Directly after KEX, Go rejects by name (`server.go:435-436`).
- **Source:**
  - OpenSSH `auth2.c:197-215` `input_service_request`: accepts only `ssh-userauth` while `!authctxt->success`; everything else -> `ssh_packet_disconnect(ssh, "bad service request %s", service)`.
  - Dropbear `svr-service.c:57-61`: `ssh-connection` with `authdone != 1` -> `dropbear_exit("Request for connection before auth")`; `svr_dropbear_exit` logs, sleeps `UNAUTH_CLOSE_DELAY` (default 0), `session_cleanup()`; no DISCONNECT is sent.
    For unknown names, line 70 even says `/* TODO this should be a MSG_DISCONNECT */`.
  - Go `server.go:431-437`: one service request, must be `ssh-userauth`, else error; `NewServerConn` (`server.go:373-376`) then `c.Close()` with no DISCONNECT.
- **RFC adjudication:** RFC 4253 s10 "If the server rejects the service request, it SHOULD send an appropriate SSH_MSG_DISCONNECT message and MUST disconnect."
  ssh-connection is meant to start after authentication (RFC 4252 s5 "The 'service name' specifies the service to start after authentication"), so rejecting it here is correct for all three.
  All three disconnect (MUST met); OpenSSH also sends the DISCONNECT (SHOULD met); Dropbear and Go do not (SHOULD missed).
  Label: SHOULD-level divergence in error reporting, no state-machine difference, no security impact.

## E2: SERVICE_REQUEST "ssh-connection" after successful authentication

Claim: `... SR_AUTH UA_PK_OK SR_CONN` (also with `CH_OPEN` before it): OpenSSH `UNIMPL`, Dropbear `SR_ACCEPT`, Go `NO_CONN`.

- **H2.1: mapper-specific.** Refuted.
  Stock paramiko `srconn_postauth` and `srconn_postauth_chan`, strict on/off, 2 reps each:
  - OpenSSH: `3(unimpl seq 5)` (seq 2 with strict KEX; seq 7 / 4 when a channel was used first), then `exec id` -> `uid=1000(tester)` (8/8).
  - Dropbear: `6(accept ssh-connection)`, then `exec id` works (8/8).
  - Go: no packet, EOF 0-1 ms after the send, no DISCONNECT, no exec possible (8/8); server log only `connection closed`.
- **H2.2: OpenSSH's UNIMPL is a race with its post-auth GLOBAL_REQUEST (hostkeys-00) or channel traffic.** Refuted.
  The rejected sequence number is exactly the SERVICE_REQUEST's outgoing seq in every run (out `5(seq 5)` -> in `3(unimpl seq 5)`, etc.).
- **H2.3: the state is damaged afterwards / the answer is late.** Refuted.
  `SR_CONN DEBUG DEBUG` -> OpenSSH `UNIMPL NO_RESP NO_RESP`, Dropbear `SR_ACCEPT NO_RESP NO_RESP`; `SR_CONN CH_OPEN` -> `CH_OPEN_SUCCESS` on both; a second SR_CONN gives `UNIMPL` / `SR_ACCEPT` again; after a post-auth rekey the outcome is the same (5/5 each).
  Dropbear's accept changes nothing: `SR_CONN UA_PK_OK` -> `SR_ACCEPT NO_RESP` (UA still silently ignored as in C2), and paramiko's exec works.
  Go closes in every variant, including after a rekey and with an open channel.
- **Source:**
  - OpenSSH `serverloop.c:876-899` `server_init_dispatch` (post-auth process): default `dispatch_protocol_error`, no SERVICE_REQUEST handler -> UNIMPLEMENTED.
  - Dropbear `svr-service.c:57-66`: `ssh-connection` with `authdone == 1` -> `send_msg_service_accept`, no other effect.
  - Go `mux.go:254-273`: any message other than channel open / global / ping is treated as a channel message; bytes 1-4 (the string length, 14) are read as a channel id, `handleUnknownChannelPacket` returns `ssh: invalid channel 14` (`mux.go:386-387`) and the connection closes.
    Our Go server does not log mux errors, so the "invalid channel 14" text is inferred from source, not observed.
- **RFC adjudication:** unspecified.
  RFC 4253 s10 describes the single request that follows key exchange; RFC 4252 s5 starts ssh-connection through the USERAUTH_REQUEST service field; no text addresses a SERVICE_REQUEST after authentication.
  Under a literal per-request reading of s10 ("accept" or "disconnect"): Dropbear accepts (consistent), Go disconnects without the SHOULD DISCONNECT, OpenSSH's UNIMPLEMENTED is neither (RFC 4253 s11.4 UNIMPLEMENTED is for unrecognised message numbers, and 5 is recognised).
  Same label as C3: unspecified divergence; Go's teardown of an authenticated session is the most severe, but nothing in the RFC forbids it.

## Side notes

- E1 and E2 add no new mechanism; for the report they belong to the "silent close" pattern (E1) and to C3 (E2).
- The probe and the mapper replay ran concurrently (2 jobs) against the same servers, so the probe's server-log windows also contain lines from the mapper's connections (client `SSH-2.0-paramiko_3.1.0`); attribute log lines by client ident/port.
  The client-side wire logs are unaffected.
- Timestamps in the probe are rounded to 1 ms, so `out_after_injection` sometimes also lists the preceding SR_AUTH, and `in_after_injection` in `srconn_after_sr` lists the SERVICE_ACCEPT for ssh-userauth that arrived just before the injection.
  The injected packet is the last type-5 entry; nothing arrives after it on Dropbear or Go.

## What I touched / broke

- Nothing broken: RestartCount 0 and state running for `psm-mapper-{openssh,dropbear,gossh}` and `psm-{openssh,dropbear,gossh}` after the runs; no `~/self-impl-errorlog.txt`.
- No Python or Docker locally; all runs via `./gx`; no changes to vendor/, psm/, suts/, tests/; nothing committed.
- New files: `scratch/review/srconn_probe.py`, `scratch/review/srconn_seqs.json`, `results/review/srconn_replay.json`, `results/review/srconn_probe.json`, `results/review/srconn_source_excerpts.txt`, this file.
