# Stream A: harness-vs-harness disagreements (v2)

Harnesses compared on the same live servers (OpenSSH 10.0p1 :2201, Dropbear 2025.88 :2202, Go x/crypto 0.58.0 :2203):
- **ours**: published ssh-fuzzer mapper (Paramiko-based) with patches P1-P5, DH group14-sha256, publickey auth, non-strict KEX, own instances `psm-a-mapper-*` on 8401-8403 (`scripts_v2/a_start_mapper.sh`).
- **theirs**: teammate mapper `vendor/agentic-protocol-state-learning` @ 76b49e1 (`src/smlearn/ssh/mapper.py`, written by Codex from the RFCs), curve25519, password auth, timeout 0.4 s / quiet 0.1 s as in their published runs; run unchanged from a separate venv (`scripts_v2/tm_common.py`).
- **third client**: stock paramiko 5.1.0 `Packetizer` on a raw socket (framing only, no paramiko KEX state machine), so it can send exactly either harness's message order (`scripts_v2/third_probe.py`).

Vocabulary map: `results/v2/A/alphabet_map.json` (version A-1).
Verdict categories: **ours wrong**, **theirs wrong**, **setup/abstraction difference** (both harnesses report correctly what the server did with the bytes each sent).

## Part 1: v1 sequences replayed through their mapper

Input: all 64 replayed v1 sequences (`results/final/verified_all.json`, which contains every sequence of `reference/final_check_seqs.json` and every one of the 39 divergence points in `results/final/divergence_points.txt`), on all 3 servers, 3 repetitions each, compared step by step with our recorded mapper outputs.
Script `scripts_v2/tm_xreplay.py`; output `results/v2/A/xreplay_nonstrict.json` (strict_kex=False) and `results/v2/A/xreplay_strict.json` (strict_kex=True, their default).
Our mapper was re-run on one representative per class, 5 reps, and reproduced the v1 outputs exactly (`results/v2/A/ours_replay_classes.json`).

### Non-strict (the like-for-like setting)

| | (sequence, server) pairs | agree at every step | mismatch |
|---|---|---|---|
| first input KEXINIT | 120 | **120** | 0 |
| first input KEX30 / NEWKEYS / SR_AUTH (our mapper adds a KEXINIT) | 72 | 7 | 65 |
| total | 192 | 127 | 65 |

Their mapper was deterministic on all 192 pairs (3 of 3 reps identical).
The 65 mismatches reduce to 8 classes (server, diverging prefix, outputs) and two mechanisms.

#### H1 (M1): our automatic KEXINIT — setup/abstraction difference — 40 pairs, 4 classes

| server | sequence (diverging input in bold) | ours | theirs | pairs |
|---|---|---|---|---|
| OpenSSH | KEX30 **KEX30** | KEX31+NEWKEYS | UNIMPL | 19 |
| Dropbear | KEX30 **KEX30** | KEX31+NEWKEYS | UNIMPL | 19 |
| OpenSSH | KEX30 **KEXINIT** | UNIMPL | NO_RESP | 1 |
| Dropbear | KEX30 **KEXINIT** | NO_CONN | NO_RESP | 1 |

Mechanism: when our mapper reads the server KEXINIT before having sent its own, it sends one automatically (upstream `transport.py` ~2827, documented in `vendor/PATCHES.md` and v1 review H5.1).
So our abstract `KEX30` is the wire sequence `30, 20`; theirs is just `30`.
After `KEX30` the server has a client KEXINIT in our run but not in theirs, so a second KEX30 starts a real exchange for us and is a protocol error for them, and a later KEXINIT is a duplicate for us but the first one for them.
Third client (`results/v2/A/third_probe.json`, 3 reps, both orders):
OpenSSH and Dropbear answer `30` with UNIMPLEMENTED and a second `30` with UNIMPLEMENTED (their order), but `30, 20, 30` with `31, 21` (our order); `30, 20` is accepted silently on both.
Both harnesses therefore report the server correctly for what they sent.
Verdict: **setup/abstraction difference** (our symbol `KEX30` as a first input means "KEX30 then KEXINIT").
Not a server finding; it confirms v1's caveat that our models cannot say whether a server would run a KEX without any client KEXINIT.

#### H2 (M2): a close in the same step as the server KEXINIT — setup/abstraction difference — 25 pairs, 4 classes

| server | sequence | ours (first step, server KEXINIT stripped) | theirs | pairs |
|---|---|---|---|---|
| Go | **KEX30** | NO_RESP (raw `KEXINIT`, then NO_CONN at the next step) | NO_CONN (raw `CLOSED`) | 22 |
| Go | **NEWKEYS** | NO_RESP | NO_CONN | 1 |
| Go | **SR_AUTH** | NO_RESP | NO_CONN | 1 |
| Dropbear | **SR_AUTH** | NO_RESP | NO_CONN | 1 |

Mechanism: the server closes the TCP connection right after the first non-KEXINIT packet.
Our mapper reports the server's KEXINIT in that step and does not show a close that happens in the same step as a message (v1 report, "abstraction hides"; v1 review H5.2); the close appears one step later as NO_CONN.
Their mapper absorbed the server KEXINIT in `reset()`, so it reports the close in the step where it happens.
Third client: Go closes right after `30`, `21` or `5` in both orders (before our extra KEXINIT could matter); Dropbear closes right after `5` in both orders; 3 of 3 reps (`results/v2/A/third_probe.json`; Go log: `first packet should be msgKexInit`).
Verdict: **setup/abstraction difference**; the servers behave the same for both harnesses, ours is less precise about when the connection ends.

### Strict KEX on (their default)

Same 192 pairs (`results/v2/A/xreplay_strict.json`): the 65 mismatches above, plus 8 more, all inside the initial key exchange:

| server | sequence | ours (non-strict) | theirs (strict) |
|---|---|---|---|
| OpenSSH | KEXINIT **NEWKEYS** | UNIMPL | DISCONNECT |
| OpenSSH | KEXINIT KEX30 **KEX30** | UNIMPL | DISCONNECT |
| OpenSSH | KEXINIT **KEXINIT** | UNIMPL | DISCONNECT |
| OpenSSH | KEXINIT **SR_AUTH** | UNIMPL | DISCONNECT |
| OpenSSH | KEXINIT KEX30 **KEXINIT** | UNIMPL | DISCONNECT |
| OpenSSH | KEXINIT KEX30 **SR_AUTH** | UNIMPL | DISCONNECT |
| Dropbear | KEXINIT **NEWKEYS** | UNIMPL | NO_CONN |
| Dropbear | KEXINIT KEX30 **KEX30** | UNIMPL | NO_CONN |

Verdict: **setup difference (strict KEX)**.
This is exactly what v1 predicted from its stock-paramiko strict-KEX probes (`results/review/kex_phase.md` K1/K2: OpenSSH DISCONNECT "strict KEX violation"; `results/review/remaining_classes.md` C4: all three terminate under strict KEX), now reproduced by a second, independent mapper.
It confirms v1's statement that D7, D8 and the initial-KEX members of D9 exist only on the non-strict branch.
One strict pair had 2 instead of 3 repetitions (connection setup to Dropbear failed 4 times; Dropbear allows 5 unauthenticated connections per IP and several harness jobs shared it): an infrastructure failure, not nondeterminism.

## Part 2: learned models (their learner + mapper on our servers) vs our models

Status: see `results/v2/A/summary.md` (filled in as runs finish).
