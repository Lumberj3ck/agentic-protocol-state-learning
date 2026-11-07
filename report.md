# Do independent SSH servers agree on the transport/auth state machine?

Status: DRAFT (results sections are filled as evidence lands; see JOURNAL.md).

## Answer

**On the normal handshake, yes: OpenSSH 10.0p1, Dropbear 2025.88 and Go x/crypto/ssh 0.58.0 agree exactly.**
Key exchange, service request, public-key authentication, channel open and rekey after authentication produce the same outputs on all three (`results/final/verified_B_only.md`, row 11).

**Off the normal path they disagree a lot, and systematically.**
Learned models and three-server replays give 39 distinct divergence points, all deterministic and none explained by the test harness, in nine classes (table below; `results/final/verified_all.md`).
Each server applies one consistent policy to a message in the wrong place:
- Go closes the connection without a word;
- OpenSSH answers UNIMPLEMENTED and carries on;
- Dropbear tends to accept.

**Who follows the RFCs:**
- Measured against MUSTs, Go and Dropbear met every one we tested.
- OpenSSH breaks the letter of two:
  - RFC 4252 §6: it does not disconnect on connection-protocol messages before authentication (D2).
  - RFC 4253 §9: it refuses a client rekey before authentication (D3).
  We found no security impact for either: the messages are not parsed, and the refusal is deliberate.
- Against SHOULDs:
  - Dropbear is the only one that silently ignores authentication requests after success (D4).
  - OpenSSH is the only one that sends a DISCONNECT message when it disconnects (D6).
- Most other differences (D1, D5, D7, D8, D9) are in territory the RFCs leave unspecified, and D7/D8 disappear when strict KEX is negotiated.

**Are they real?**
- Every class was replayed against all three servers (5 to 10 repetitions, 0 nondeterministic runs).
- A skeptical-review agent tried and failed to explain each as a harness artifact, using an independent client (stock paramiko, other key exchange, strict KEX on and off) and the servers' own logs and source.
- Along the way the harness itself produced artifacts that would have looked like findings: a wrong exchange-hash input, a crashing input, and a corrupted encrypted stream after a misplaced NEWKEYS. Those were caught, fixed or filtered, and are listed under Method.

**Old findings still hold.**
NDSS 2023's Dropbear "authentication without service request" (D1) and SPIN 2017's OpenSSH "no rekey before authentication" (D3) are unchanged in the 2025 releases.
Dropbear's learned model is identical across 2020.81, 2022.83 and 2025.88.

## Question

Do independent open-source implementations of the SSH transport (RFC 4253) and user-authentication (RFC 4252) handshake agree on their protocol state machine?
Where they disagree, which side follows the RFCs, and is the disagreement a confirmed behavioural difference or an artifact of our test harness?

## Setup

All servers ran in Docker on the GX10 box, bound to 127.0.0.1 only; nothing outside the box was contacted.

| SUT | Version | Pinning | Notes |
|---|---|---|---|
| OpenSSH | 10.0p1 (`SSH-2.0-OpenSSH_10.0`) | Alpine 3.22 `openssh-server=10.0_p1-r11`, base digest in `suts/openssh/VERSION.md` | `PerSourcePenalties no`; RSA host key and `KexAlgorithms +diffie-hellman-group14-sha256` added for the mapper |
| Dropbear | 2025.88 (`SSH-2.0-dropbear_2025.88`) | Alpine 3.22 `dropbear=2025.88-r1` | RSA host key added |
| Go x/crypto/ssh | v0.58.0 (`SSH-2.0-Go`), Go 1.26.0 | `suts/gossh/go.mod` + `go.sum` | minimal server in `suts/gossh/main.go`; RSA host key added |
| Dropbear (validation only) | 2020.81 | Alpine 3.13 `dropbear=2020.81-r0` | the version analysed in NDSS 2023 |

## Method

We build on the published method rather than from scratch (`notes/literature.md`).
de Ruiter & Poll (USENIX Sec 2015) learned TLS state machines with a mapper and LearnLib and treated model differences as leads to be checked by hand.
Fiterau-Brostean et al. (SPIN 2017; NDSS 2023) did the same for SSH with a mapper built on a heavily modified Paramiko.
We reuse that mapper unmodified except for three small patches (`vendor/PATCHES.md`): an opt-in algorithm profile for current servers, credentials from the environment, and a crash fix when the learner disconnects.
We wrote no SSH protocol or crypto code ourselves.

- Learner: AALpy 2.0.0 L* (`psm/learn.py`) talking to the mapper's line protocol (`psm/mapper_client.py`).
- Abstraction (the published one): one input symbol per client message; the output is the `+`-joined names of all server messages received in a fixed window, `NO_RESP` if none, `NO_CONN` once the TCP connection is closed (a sink). The mapper drops server `IGNORE`/`DEBUG`.
- Identical mapper settings for every compared SUT (published "Dropbear" timing profile: 0.3 s first-response / 0.35 s total window, 0.25 s between inputs).
- Nondeterminism: every query is checked against a prefix cache; any conflict, and a random 10% of fresh queries, are re-run and decided by majority, and every event is logged (`results/learning/<sut>/nondet.jsonl`), so it cannot silently corrupt a model (`psm/robust_sul.py`).
- Equivalence: random walks from every learned state (AALpy `StatePrefixEqOracle`).
- Diff: product-automaton BFS for shortest distinguishing sequences (`psm/diff.py`).
- Evidence: every reported disagreement is replayed as a concrete sequence against all servers, repeated, with each observation and the server's own log stored under `results/replay/` (`psm/replay.py`).
- A skeptical reviewer subagent tries to explain each disagreement as a harness artifact before we accept it (`results/review/`).

## Validation: reproducing published results first

Before trusting anything on current releases, we checked the harness against what the original authors published.

1. The published finding reproduces on the version they analysed.
   On Dropbear 2020.81, `KEXINIT KEX30 NEWKEYS UA_PK_OK` gives `KEXINIT KEX31+NEWKEYS+EXT_INFO NO_RESP UA_SUCCESS`: authentication succeeds without any SERVICE_REQUEST, the NDSS 2023 "Missing SERVICE_REQUEST_USERAUTH" finding (`results/replay/smoke_dropbear2020.json`).
2. All four counterexample traces recorded by the original authors (`vendor/ssh-fuzzer/ssh-learner/output/DROPBEAR_SERVER_1683485573153/statistics.txt`) replay symbol for symbol, 3 of 3 repetitions (`results/replay/published_cex_dropbear2020.json`).
3. Our first learned model was wrong on one of those published traces (`results/checks/dropbear2020_v1.json`): it merged "authenticated, then rekeyed" with "not yet authenticated".
   The cause was our equivalence oracle (random words), not the mapper; with walks from every state the model grows from 7 to 9 states and predicts all 8 replayed traces (`results/checks/dropbear2020_v2.json`).
   This is the main methodological lesson: the mapper reproduced the published behaviour immediately, while the equivalence check is where an under-learned model hides.
4. Our 2020.81 model and the published (unfinished; the run timed out after 12 h) 2022.83 model differ on only 2 transitions, both after a first message of KEX30 (`results/diff/dropbear2020_vs_published2022.json`); our side of both replays 5 of 5 on 2020.81 (`results/replay/dropbear2020_vs_published_diffs.json`).
   To tell a version change from a gap in the published model, we also learned Dropbear 2022.83 itself, the version the published model was learned on.
   Our 2022.83 model is equivalent to our 2020.81 model (`results/diff/dropbear2022_vs_2020.json`) and predicts all four published traces (`results/checks/dropbear2022_vs_published_traces.json`), yet it differs from the published 2022.83 model on the same two transitions (`results/diff/dropbear2022_vs_published2022.json`); our side replays 10 of 10 on 2022.83 (`results/replay/dropbear2022_vs_published_diffs.json`).
   So it is not a version change.
   It is not caused by our mapper patches either: the unpatched upstream mapper gives the same answers (`results/replay/dropbear2022_upstream_mapper_check.json`).
   The remaining explanations, which we cannot separate today, are the published run's from-source Dropbear build versus our Alpine package, its environment, or the published hypothesis being incomplete (that run stopped at its 12 h limit without converging).
   Both transitions lie on an unusual path (KEX30 sent before the client's KEXINIT), and the mapper sends its own KEXINIT automatically there, which makes this path the most timing- and implementation-sensitive one in the model.

## Results

### Where the three servers agree

On the normal handshake they agree exactly.
`KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK CH_OPEN` gives the same outputs on OpenSSH 10.0p1, Dropbear 2025.88 and Go x/crypto/ssh 0.58.0 (`results/final/verified_B_only.md` row 11), once OpenSSH's `hostkeys-00@openssh.com` GLOBAL_REQUEST after UA_SUCCESS is set aside.
That message is an OpenSSH extension, confirmed by sshd's own `notify_hostkeys` log line (`results/replay/A_dropbear_vs_gossh_replay.json`), and is normalised before comparison (`reference/normalize.json`).
All three accept a rekey after authentication (`results/final/verified_A_prelim.md` rows 12-13, prefix), and none of them opens a channel before authentication (`results/review/ch_open_preauth.md`).
Every disagreement below is outside the normal handshake: it is how a server reacts to a message in the wrong place.

### Confirmed disagreements

The 64 replayed sequences reduce to 39 distinct divergence points (`results/final/divergence_points.txt`), grouped here into nine classes.
Each row was replayed as a concrete sequence against all three servers (5 to 10 repetitions, all deterministic), survived a skeptical review that tried to explain it as a harness artifact, and was reproduced with an independent client (stock paramiko 5.1.0, other key exchange, strict KEX on and off) unless noted.
Outputs are the mapper's: `NO_CONN` means the TCP connection was closed without an SSH DISCONNECT message.

| ID | Situation (shortest sequence) | OpenSSH 10.0p1 | Dropbear 2025.88 | Go x/crypto 0.58.0 | RFC | Who follows the RFC | Evidence |
|---|---|---|---|---|---|---|---|
| D1 | Correctly signed USERAUTH_REQUEST with no prior SERVICE_REQUEST (`KEXINIT KEX30 NEWKEYS UA_PK_OK`) | UNIMPL, connection kept | **UA_SUCCESS**, usable session (`exec id` works) | closes | No MUST: RFC 4253 §10 and RFC 4251 §1 only describe the order | All permitted; Dropbear is the outlier (NDSS 2023 "Missing SERVICE_REQUEST_USERAUTH", maintainer: design choice) | `results/review/ua_without_sr.md`, `results/replay/A_dropbear_vs_gossh_replay.json` |
| D2 | Channel open (message 90) before authentication (`KEXINIT KEX30 NEWKEYS [SR_AUTH] CH_OPEN`); also 80, 94, 98 | **UNIMPL, connection kept** until LoginGraceTime | closes | closes | RFC 4252 §6: MUST disconnect, "preferably" with DISCONNECT | Dropbear, Go; OpenSSH violates the letter (no security impact: payload never parsed) | `results/review/ch_open_preauth.md`, `results/final/verified_B_only.md` rows 9-10 |
| D3 | Client-initiated rekey before authentication (`KEXINIT KEX30 NEWKEYS [SR_AUTH] KEXINIT`) | **UNIMPL** (refuses) | rekeys | rekeys | RFC 4253 §9: "MUST respond with its own SSH_MSG_KEXINIT" | Dropbear, Go; OpenSSH violates the letter, deliberately (`packet.c`: "client can't cope with rekeying pre-auth"); same as SPIN 2017 on 6.9p1 | `results/review/remaining_classes.md` (C1), `results/final/verified_A_prelim.md` rows 6, 8, 11 |
| D4 | Another USERAUTH_REQUEST after USERAUTH_SUCCESS | UNIMPL | silently ignored | **closes the logged-in session** | RFC 4252 §5.1: "SHOULD be silently ignored" | Dropbear; OpenSSH and Go deviate from a SHOULD (Go parses it as a channel message: "invalid channel 6") | `results/review/remaining_classes.md` (C2), `results/final/verified_A_prelim.md` row 10 |
| D5 | Second SERVICE_REQUEST, or one after authentication (`... SR_AUTH SR_AUTH`, `... UA_PK_OK SR_AUTH`, `... UA_PK_OK SR_CONN`) | accepts the 2nd pre-auth; UNIMPL after auth | accepts both | closes | Not specified | Unspecified divergence | `results/review/remaining_classes.md` (C3), `results/review/sr_conn.md` (E2), `results/final/verified_B_only.md` rows 1-3 |
| D6 | SERVICE_REQUEST "ssh-connection" before authentication | DISCONNECT | closes, no DISCONNECT | closes, no DISCONNECT | RFC 4253 §10: SHOULD send DISCONNECT and MUST disconnect | All meet the MUST; only OpenSSH meets the SHOULD | `results/review/sr_conn.md` (E1: OpenSSH DISCONNECT code 2 "bad service request"; Dropbear/Go close within 2 ms, no packet), `results/final/verified_B_only.md` rows 7-8 |
| D7 | Protocol errors inside a key exchange: NEWKEYS before KEX30, duplicate KEX30, NEWKEYS in a rekey without KEX30 | UNIMPL, KEX can continue | UNIMPL, KEX can continue | closes | Not specified by RFC 4253; the strict-KEX draft requires disconnect in the initial KEX | Only on the non-strict branch: with strict KEX all three disconnect | `results/review/remaining_classes.md` (C4), `results/final/verified_A_prelim.md` rows 3, 4, 12, 13 |
| D8 | KEX30 or NEWKEYS (or SERVICE_REQUEST) as the very first message, before the client KEXINIT (the mapper then sends its KEXINIT automatically) | KEXINIT+UNIMPL | KEXINIT+UNIMPL for KEX30/NEWKEYS; KEXINIT then closes for SR_AUTH | KEXINIT, then closes | Not specified; strict KEX requires KEXINIT first | Non-strict branch only; with strict KEX all three disconnect | `results/review/remaining_classes.md` (C5), `results/final/verified_A_prelim.md` rows 1-2 |
| D9 | Messages out of place in or around a key exchange: duplicate KEXINIT, SERVICE_REQUEST during KEX, KEX30 or a second NEWKEYS outside any KEX, and SERVICE_REQUEST / USERAUTH_REQUEST / duplicate KEXINIT during a post-auth rekey (18 divergence points) | UNIMPL, connection kept | closes | closes | RFC 4253 §7.1 constrains only the sender ("MUST NOT send"); the receiver is unspecified | Unspecified divergence: OpenSSH ignore-and-report vs fail-closed | KEXP_REVIEW, `results/final/divergence_points.txt` |

### The pattern behind the rows

The disagreements are not random: each implementation applies one consistent policy to unexpected messages.

- **Go x/crypto/ssh: fail closed, silently.** Every unexpected message in any state ends the connection, with no UNIMPLEMENTED and no DISCONNECT (server logs: `unexpected message type N (expected one of [...])`).
  This is the strictest and simplest state machine, and it meets every MUST we tested, but it skips the SHOULD-level DISCONNECT and turns a harmless post-auth duplicate request into a dropped session (D4).
- **OpenSSH: ignore and report.** Before authentication sshd routes every message it does not expect to `dispatch_protocol_error`, which answers UNIMPLEMENTED and carries on (`auth2.c`, `dispatch.c`).
  That single design choice explains D1, D2, D3 and D4 for OpenSSH, including its two letter-of-the-RFC violations (§6 and §9), neither of which has a security effect we could find.
- **Dropbear: permissive.** It accepts out-of-order service requests and authentication (D1, D5), rekeys anywhere, and is the only one to follow RFC 4252 §5.1's SHOULD on repeated authentication (D4).
  Its learned model on this alphabet is identical for 2020.81, 2022.83 and 2025.88 (`results/diff/dropbear2025_vs_2022_A.json`, `results/diff/dropbear2025_vs_2020_A.json`): five years of releases did not change this behaviour.

### Relation to earlier findings

- NDSS 2023's Dropbear "Missing SERVICE_REQUEST_USERAUTH" (v2020.81) still holds in 2025.88 (D1).
- SPIN 2017's OpenSSH "Rekey Fail Before Auth" (6.9p1) still holds in 10.0p1 (D3).
- OpenSSH answering pre-auth channel messages with UNIMPLEMENTED (D2) is visible in the SPIN 2017 6.9p1 model and in the CCS 2025 9.9p2 model, but we found no earlier work classifying it against RFC 4252 §6 (`results/review/ch_open_preauth.md`, Q5).
- CCS 2025 (Bäumer et al.) reports OpenSSH and Go as compliant and Dropbear as lifting restrictions too early; our results agree for Dropbear and Go.
  For OpenSSH the difference is one of judgement rather than observation: their published 9.9p2 model shows the same UNIMPLEMENTED self-loops, but their analysis of channel messages stops at SERVICE_ACCEPT (`results/review/ch_open_preauth.md`, Q5); we did not check how they classified pre-auth rekey.

### Model status

- Alphabet A (published 5 inputs), rekey-aware equivalence oracle, converged for all three current servers: OpenSSH 9 states, Dropbear 9, Go 12 (`results/models/A_*.dot`); each predicts every replayed trace on its alphabet (`results/checks/A_*_vs_replays.json`, 0 mismatches).
- Alphabet B (+ SR_CONN, CH_OPEN) converged for Dropbear (13 states) and Go (16); restricted to A they are equivalent to the A models (`results/diff/B_vs_A_*_restricted.json`). OpenSSH's B run was stopped unconverged at 15:01; its B-only behaviour rests on replays alone (`results/final/verified_B_only.md`).
- State counts are not a measure of implementation complexity: they include states made by the mapper (CH_MAX, the stream corrupted after NEWKEYS without a key exchange; `vendor/PATCHES.md`).

## What the method cannot conclude

- **An unlearned transition is not proof of absence.**
  A learned model is only as good as the equivalence check.
  Ours twice produced plausible, wrong models (Dropbear v1, Go with state-prefix walks) that a deeper test exposed (`results/checks/dropbear2020_v1.json`; JOURNAL 13:21, 13:29).
  "Server X has no state where Y happens" means only "we did not find one with these tests".
  Every behavioural claim in this report therefore rests on a replayed concrete sequence, not on the model alone.
- **The alphabet bounds the conclusions.**
  We learned 5 inputs (the published alphabet) and 7 with SR_CONN and CH_OPEN.
  No other message types, no malformed fields, no strict KEX (the published mapper never offers `kex-strict-c-v00@openssh.com`), no ext-info, no keyboard-interactive, one key exchange method (`diffie-hellman-group14-sha256`, which OpenSSH 10.0 only offers because we re-enabled it).
  The Terrapin-era strict-KEX rules are therefore untested here.
- **The abstraction hides some behaviour.**
  The mapper reports all messages that arrive within 0.35 s as one symbol, drops server IGNORE/DEBUG, does not show a TCP close that happens in the same step as a message, and caps channels at one (`CH_MAX` is a mapper-made symbol).
  DISCONNECT reason codes are not part of the output.
- **Configuration matters.**
  We changed only what the mapper needed (RSA host key, one DH group in OpenSSH, `PerSourcePenalties no`); other defaults (MaxAuthTries, LoginGraceTime) were not varied.
- **One version per implementation** for the current-release comparison, and one host (localhost, low latency); timing-dependent behaviour under load was not studied.

## Cost of the research loop, and what an agent can automate

Full per-run numbers: `results/loopcost_table.md` (generated by `psm/costs.py` from `results/learning/*/stats*.json` and the intervention log `results/loopcost.jsonl`).

Per implementation (fresh queries actually sent to the server; the rest were answered from the cache or the NO_CONN sink):

| Implementation | Mapper fixes it triggered | Converged runs: fresh queries / steps / minutes | Runs that did not converge or were superseded | Nondeterminism events | Human corrections specific to it |
|---|---|---|---|---|---|
| OpenSSH 10.0p1 | 1 (P4, exchange-hash input after a duplicate KEXINIT; surfaced as a learner crash) | A: 341 / 3133 / 46 (+365 answers reused from the stopped B run) | A with state-prefix oracle (~20 min, stopped after hypothesis 1); B (~80 min, stopped unconverged) | 0 (35 random repeats) | 0 |
| Dropbear 2025.88 | 0 | A: 162 / 860 / 12; A re-check with rekey oracle: 59 / 455 / 6.5; B: 327 / 2443 / 34 | none | 0 | 0 |
| Go x/crypto 0.58.0 | 0 | A: 53 / 441 / 6 (rekey oracle); B: 172 / 1252 / 16.5 | A with state-prefix oracle: converged to a wrong 8-state model (4 min) | 0 | 0 |
| Dropbear 2020.81 / 2022.83 (validation) | 1 (P3, mapper crash when the learner disconnects; found by the first smoke test) | 2020.81: 111 + 66 / 437 + 481 / 6 + 7; 2022.83: 162 / 860 / 12 | 2020.81 v1 converged to a wrong 7-state model | 0 | 0 |
| Shared harness | P1, P2 (setup for current servers); P5 and the NEWKEYS taint filter (both found by reviewer subagents); two equivalence-oracle upgrades; crash-surviving learner | | | | 3 (user: reuse the published mapper and validate first; disk/image rule; stale CLAUDE.md and missing README) |

In total: 5 mapper patches, 1 harness filter, 2 oracle upgrades, 3 human corrections by the user, 4 skeptical reviews.
OpenSSH cost about 5x more learning time than Dropbear or Go for the same alphabet: it answers out-of-order messages with UNIMPLEMENTED and keeps the connection, so far fewer queries end in the cheap NO_CONN sink.

### What an agent did end to end

- **Building and pinning the targets.** Three parallel subagents each produced a pinned, verified server container in 1 to 4 minutes (`suts/*/VERSION.md`).
- **Literature.** One subagent extracted the earlier SSH findings and the exact RFC clauses (`notes/literature.md`); those notes chose the reproduction targets and the RFC adjudications.
- **Learning, diffing, replaying.** Fully automatic once the mapper worked: models were learned in 4 to 34 minutes per run for Dropbear and Go; every cross-server difference was turned into a replayed sequence by script (`psm/diff_to_seqs.py`, `psm/replay.py`, `psm/verify.py`).
- **Finding its own harness bugs.** The skeptical-review subagents were the most valuable part of the loop.
  They found two mapper bugs that would have corrupted results (P5: user messages crashed the mapper; the NEWKEYS-without-KEX stream corruption, now filtered by `psm/taint.py`) and confirmed eight disagreement classes three ways each (mapper replay, independent paramiko client, server source).
  P4 (a wrong exchange-hash input after a duplicate KEXINIT) surfaced as a learner crash on OpenSSH and was diagnosed by the agent from the mapper log.

### Where it still needed a human, or would have

- **Choosing not to build the risky part.** The agent's first plan was to write its own SSH client engine; that stopped, and the user redirected to reusing the published mapper and to a validation-first, one-server-first plan.
  That redirection is what made the results trustworthy: reusing the published mapper let us check our harness against published traces symbol for symbol.
- **Knowing when a plausible model is wrong.** The agent's own learning loop twice produced plausible, wrong models.
  It noticed the first only because published traces existed to check against, and the second only because a model looked structurally suspicious (authentication state lost after a rekey).
  For a protocol without published reference traces, a human with protocol knowledge would need to choose the targeted equivalence tests (here: "rekey must preserve state", RFC 4253 §9).
- **Shared-resource judgement.** The agent pruned the whole box's Docker build cache (other users' too) while freeing disk; the user then set the rule "remove only our own images" (JOURNAL 12:58).
  Earlier the agent itself caught that the provided `gx` script would have synced into another project's directory and overwritten its files.
- **Adjudication and disclosure.** The agent can quote the RFC and classify MUST vs SHOULD vs unspecified, but whether OpenSSH's two letter-of-the-RFC deviations deserve a report to the maintainers, and how to phrase "violation without security impact", is a human call.

### Agent mistakes, for the record

`docker builder prune -af` on a shared box; `pkill -f` matching its own shell; a broken run-script edit that briefly took the three current servers down; small local `python3` runs against the project rule (twice by the lead, once by a reviewer); a replay-tool edit that dropped all but the last sequence (caught by a test before use).
All are in JOURNAL.md.
