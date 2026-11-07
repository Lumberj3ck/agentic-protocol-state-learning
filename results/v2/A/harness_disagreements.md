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

Their learner (`smlearn.learn`: RobustSUL with majority vote, ParallelEqOracle with their SSH seed paths, AALpy KV), unchanged, driven against our containers by `scripts_v2/tm_learn.py`; 3 mapper instances; alphabet KEXINIT, KEX30, NEWKEYS, SR_AUTH, SR_CONN, UA_PW_OK, CH_OPEN.
Models: `results/v2/A/tm_models/<sut>_<nonstrict|strict>/` (model.dot, learn.json, queries.jsonl).

| server | their model, non-strict | their model, strict | our model (v1) |
|---|---|---|---|
| OpenSSH 10.0p1 | 10 states, 850 s | 12 states, 727 s | A_openssh, 9 states (5 inputs; our B run never converged) |
| Dropbear 2025.88 | 8 states, 477 s | 11 states, 574 s | B_dropbear, 13 states |
| Go 0.58.0 | 9 states, 484 s | 9 states (equivalent to non-strict) | B_gossh, 16 states |

0 nondeterminism events in every run.
Their models are smaller because their mapper has no artifact states: it never corrupts its stream on a stray NEWKEYS and has no one-channel cap.

Diff: `psm.xharness diff` (common vocabulary, initial state split; OpenSSH restricted to our alphabet A), `results/v2/A/xdiff_<sut>_<mode>.json`.
Every coarse class was replayed live with BOTH mappers, 3 reps each (`scripts_v2/xdiff_replay.py`, `results/v2/A/xdiff_replay_<sut>_<mode>.json`).

### Non-strict: 32 classes

| server | product transitions compared / agree | classes | H1 auto-KEXINIT | H2 hidden close | ours: NEWKEYS taint | ours: CH_MAX | theirs: learned model wrong |
|---|---|---|---|---|---|---|---|
| OpenSSH | 70 / 47 | 12 | 2 | 1 | 9 | 0 | 0 |
| Dropbear | 112 / 96 | 10 | 2 | 4 | 2 | 2 | 0 |
| Go | 112 / 101 | 10 | 0 | 6 | 0 | 2 | 2 |
| total | 294 / 244 (83%) | 32 | 4 | 11 | 11 | 4 | 2 |

In 30 of 32 classes both live harnesses reproduce their own model exactly (deterministic, 3/3); the harnesses differ live for the mechanism stated.
In the remaining 2 (Go), the live harnesses AGREE and their model is wrong.

#### H3: our NEWKEYS taint — ours wrong (known, documented in v1) — 11 classes

| server | sequence (all through our mapper's stream corruption) | ours | theirs |
|---|---|---|---|
| OpenSSH | KEXINIT KEX30 NEWKEYS NEWKEYS {KEX30, KEXINIT, NEWKEYS, UA_PK_OK} | NO_CONN | UNIMPL |
| OpenSSH | KEXINIT KEX30 NEWKEYS NEWKEYS SR_AUTH | NO_CONN | SR_ACCEPT |
| OpenSSH | KEXINIT KEX30 NEWKEYS SR_AUTH NEWKEYS UA_PK_OK | NO_CONN | UA_SUCCESS |
| OpenSSH | ... SR_AUTH UA_PK_OK NEWKEYS {KEXINIT, SR_AUTH} | NO_CONN | KEXINIT, UNIMPL |
| OpenSSH | ... SR_AUTH UA_PK_OK KEXINIT NEWKEYS KEX30 | NO_CONN | KEX31+NEWKEYS |
| Dropbear | KEXINIT KEX30 NEWKEYS KEXINIT NEWKEYS {KEX30, NEWKEYS} | NO_CONN | KEX31+NEWKEYS, UNIMPL |

Mechanism: on a NEWKEYS with no completed key exchange since the last one, our mapper re-derives the old keys and restarts its AES-CTR counter, so everything it sends afterwards is garbage to the server (`psm/taint.py`, `vendor/PATCHES.md`; the taint index is recorded per row).
Their mapper keeps its keys (MAPPER-SPEC "pending keys are consumed when installed"), so the server's real reaction is visible: OpenSSH answers the stray NEWKEYS with UNIMPLEMENTED and carries on; Dropbear answers a NEWKEYS inside a rekey with UNIMPLEMENTED and the rekey can still complete.
Third client: v1 stock-paramiko probes `k3_newkeys_{pre,sr,auth}` (OpenSSH non-strict: UNIMPLEMENTED, then auth and `exec id` succeed on the same connection; `results/review/kex_phase.md` K3) and `rekey_newkeys_no_kexdh` (`results/review/remaining_classes.md` C4), plus the pre-auth Dropbear variant in `results/v2/A/third_probe2.json` (T1/T2).
Verdict: **ours wrong** (mapper limitation, already known); v1 never reported anything at or after the taint point (`psm/verify.py`), so no v1 finding is affected.
It does mean our learned models contain artifact states that theirs does not.

#### H4: our one-channel cap (CH_MAX) — ours wrong (known limitation) — 4 classes

`KEXINIT KEX30 NEWKEYS [SR_AUTH] UA_PK_OK CH_OPEN CH_OPEN` (Dropbear, Go): ours `CH_MAX` (mapper-made, nothing sent), theirs `CH_OPEN_SUCCESS`.
`... UA_PK_OK CH_OPEN KEXINIT CH_OPEN` (Dropbear, Go): ours `CH_MAX`, theirs `NO_CONN` (a CHANNEL_OPEN inside a rekey makes both servers close).
Third client: `results/v2/A/third_probe2.json` T3 (two session channels) and T4 (CHANNEL_OPEN after the server's rekey KEXINIT).
Verdict: **ours wrong** (known mapper limitation, `vendor/PATCHES.md`; CH_MAX is not a server output).

#### H5: their Go model merges states after a pre-auth rekey — theirs wrong (learner, not mapper) — 2 classes

| sequence | ours model = ours live = theirs live | their model |
|---|---|---|
| KEXINIT KEX30 NEWKEYS SR_AUTH KEXINIT KEX30 NEWKEYS **SR_AUTH** | NO_CONN | SR_ACCEPT |
| KEXINIT KEX30 NEWKEYS SR_AUTH KEXINIT KEX30 NEWKEYS **UA_PK_OK** | UA_SUCCESS | NO_CONN |

Their 9-state Go model sends "SR_AUTH accepted, then KEXINIT" back to the state after the initial KEXINIT, i.e. it forgets the service request across a rekey.
Their own mapper, live, 3/3, gives the same answers as ours (`results/v2/A/xdiff_replay_gossh_nonstrict.json`); we did not read Go's source for this.
Their seed paths include a pre-auth rekey only before SR_AUTH, so the oracle never separated the two states.
This is the same failure mode as their own documented Go refutation (`vendor/.../results/catalogue/verified-5.json`: a merged "rekeyed, unauthenticated" state).
Verdict: **theirs wrong** (equivalence oracle / learned model; their mapper is right).
Their prescribed fix (refuted witnesses as `--seeds`) was run: `results/v2/A/tm_models/gossh_nonstrict_seeded/` (see summary for the outcome).

### Strict KEX on (their default): setup difference

Our mapper cannot negotiate strict KEX, so every extra class here is a strict-vs-non-strict comparison by construction.
Counts and replays: `results/v2/A/xdiff_<sut>_strict.json`, `results/v2/A/xdiff_replay_<sut>_strict.json`; their own strict-vs-non-strict model diffs: `results/v2/A/tm_<sut>_strict_vs_nonstrict.json` (Go equivalent; Dropbear 3 classes; OpenSSH 21 coarse classes, all initial-KEX errors (DISCONNECT) or a stray NEWKEYS, after which OpenSSH resets its receive sequence number under strict KEX, their CANDIDATE-001, so the next packet fails its MAC: CLOSED).
