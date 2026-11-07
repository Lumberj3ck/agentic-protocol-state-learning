# Stream A journal (v2)

## 2026-11-07

- 16:05 Read PROMPT v2, report v1, PATCHES, teammate README/spec/mapper/learner/catalogue.
- 16:06 Created a separate venv for the teammate harness on the box (`.venv-tm`: aalpy 2.0.0, cryptography 50.0.2 as in their uv.lock, paramiko 5.1.0); ours untouched.
  Their code is imported read-only from `vendor/agentic-protocol-state-learning/src` via `scripts_v2/tm_common.py`; no file in their repo is changed.
- 16:10 Smoke test (`scripts_v2/tm_smoke.py`, `results/v2/A/tm_smoke.json`): their mapper completes KEX, password auth, channel open, exec and post-auth rekey on our OpenSSH 10.0p1, Dropbear 2025.88 and Go 0.58.0, strict KEX on and off, deterministic over 3 reps.
  First setup difference seen: their KEXINIT does not advertise `ext-info-c`, so servers send no EXT_INFO; ours (Paramiko) does. EXT_INFO is dropped on both sides for comparison.
- 16:12 Alphabet/vocabulary map written: `results/v2/A/alphabet_map.json` (version A-1), with rationale per entry and a list of what is not mappable.
- 16:14 Quota raised by the lead (6 heavy jobs). Launched in parallel: replay of all v1 sequences through their mapper, non-strict and strict (`scripts_v2/tm_xreplay.py`), and their learner (KV + their seed-path oracle, `scripts_v2/tm_learn.py`) on our 3 SUTs, alphabet KEXINIT,KEX30,NEWKEYS,SR_AUTH,SR_CONN,UA_PW_OK,CH_OPEN, non-strict (3 runs) and strict (chained).
- 16:16 `psm/xharness.py` (common-vocabulary conversion both ways, cross-harness diff; initial state is split so only the first step loses the server KEXINIT) with `tests/test_v2_xharness.py`: 5 passed on the box.
- 16:08 (box clock from here on; earlier stamps are laptop estimates and run about 8 min ahead) Replay differential, non-strict (`results/v2/A/xreplay_nonstrict.json`): 64 v1 sequences x 3 servers through their mapper, 3 reps, 0 nondeterministic.
  120/120 pairs starting with KEXINIT agree at every step; 65 of the 72 pairs starting with KEX30/NEWKEYS/SR_AUTH disagree.
- 16:08 Strict (`results/v2/A/xreplay_strict.json`): 8 more disagreements, all initial-KEX protocol errors (OpenSSH DISCONNECT, Dropbear close), as v1's paramiko strict probes predicted; setup difference.
- 16:10 Catalogues (`scripts_v2/run_catalogues.py`): their 15 patterns + our D1-D9 patterns (`catalogue-v2/`, their JSON format) on our v1 models (converted by `psm.xharness.ours_to_theirs`) and their published models.
  The gx sync excludes every `results/` directory, so their `vendor/.../results/runs` had to be rsynced to the box separately.
- 16:12 Third-client probe first version hung: paramiko `Packetizer.read_message` retries on socket timeout; fixed with `select` before each read.
- 16:16 Third client (`results/v2/A/third_probe.json`, stock paramiko Packetizer, 3 reps, each harness's exact message order): all 16 cases deterministic.
  H1 confirmed: OpenSSH/Dropbear answer `30 30` with UNIMPL UNIMPL (their order) and `30 20 30` with `31 21` (our order).
  H2 confirmed: Go closes right after the first non-KEXINIT packet in both orders (`first packet should be msgKexInit`, `got bogus newkeys message`), Dropbear after `5` (`Unexpected packet type 5, expected 20`).
- 16:16 Our mapper on the class representatives (`results/v2/A/ours_replay_classes.json`, own mappers 8401-8403, 5 reps): identical to v1.
- 16:14 Their learner finished Dropbear non-strict (8 states, 477 s), Go non-strict and strict (9 states each).
- 16:18 Cross-harness model diff (`psm.xharness diff`) Go: 10 coarse classes; double live replay (`results/v2/A/xdiff_replay_gossh_nonstrict.json`): 6 are H2, 2 are CH_MAX (not comparable), 2 are errors in THEIR learned model: after `KEXINIT KEX30 NEWKEYS SR_AUTH KEXINIT KEX30 NEWKEYS`, their model predicts SR_AUTH -> SR_ACCEPT and UA -> NO_CONN, but their own mapper live gives NO_CONN and UA_SUCCESS, same as ours (their model merges "rekeyed after SR_AUTH" with "after the initial KEXINIT").
- 16:19 Dropbear double replay crashed on a connection-setup EOF (Dropbear MAX_UNAUTH_PER_IP 5, shared with the learners); `tm_query` now retries like their `reset_with_retry`; rerun.
- 16:19 The Write tool refused `results/v2/A/summary.md` (subagent rule against report files); its content goes to the lead in the final message instead.
- 16:20 Their learner, our servers: OpenSSH non-strict 10 states (850 s), strict 12 (727 s); Dropbear strict 11 (574 s); 0 nondeterminism events in every run.
  Their own strict vs non-strict models: Go equivalent; Dropbear 3 classes, OpenSSH 21 coarse classes, all initial-KEX errors or stray NEWKEYS (strict: CLOSED; the latter is their CANDIDATE-001 sequence-number reset).
- 16:21 Dropbear double replay (`results/v2/A/xdiff_replay_dropbear_nonstrict.json`): both harnesses reproduce their own models live on all 10 classes, 3/3 deterministic.
  Classes: 4 H2, 2 H1, 2 our NEWKEYS taint (pre-auth rekey with NEWKEYS before KEX30), 2 CH_MAX.
- 16:22 OpenSSH model diff on alphabet A: 12 classes, 3 auto-KEXINIT (H1/H2), 9 our NEWKEYS taint; double replay running.
- 16:23 Third client, OpenSSH with USERAUTH_REQUEST as the first packet: closed in both orders, 3/3 (`results/v2/A/third_probe_openssh_ua.json`): H2.
- 16:24 Catalogues (`results/v2/A/catalogue_results.json`): on the shared alphabet our models and theirs (learned on the same servers) have identical hit sets for Dropbear (8 patterns) and Go (D4, D6); OpenSSH identical on alphabet A, theirs adds CONN-BEFORE-AUTH and D2 (CH_OPEN, not in our A alphabet).
  The STRICT-KEX-* patterns hit every non-strict model; not applicable, since strict KEX was not negotiated.
- 16:24 Started their learner on the full 17-input alphabet, strict (their default), on our three servers, and a Go re-learn seeded with the two refuted words (their `--seeds` mechanism).
- 16:33 All cross-harness classes double-replayed (both mappers, 3 reps): non-strict 32 classes and strict 27 classes; every class is deterministic, and every live trace matches its own harness's model except the 2 Go H5 classes (their model wrong, their mapper agrees with ours live).
  Strict adds only strict-KEX classes (OpenSSH DISCONNECT, Dropbear close on initial-KEX errors; OpenSSH `KEX30 KEXINIT` -> DISCONNECT because the first packet was not KEXINIT).
  Under strict KEX the OpenSSH stray-NEWKEYS classes vanish by coincidence: their mapper then sees OpenSSH reset its sequence number (their CANDIDATE-001), so the next packet fails and it reports CLOSED, the same as our corrupted stream.
- 16:35 Third client, encrypted phase (`scripts_v2/third_probe2.py` -> `results/v2/A/third_probe2.json`, stock paramiko Transport, v1 rc_probe instrumentation imported unchanged, 3 reps):
  Dropbear pre-auth rekey with 1 or 2 stray NEWKEYS: UNIMPLEMENTED per NEWKEYS, then 31 21, rekey completes, auth and `exec id` succeed (theirs right, our taint is the artifact).
  Two session channels: OpenSSH, Dropbear and Go all open both and exec on the second (our CH_MAX is a mapper artifact).
  CHANNEL_OPEN inside a post-auth rekey: Dropbear and Go close; OpenSSH holds the reply (CH_OPEN_SUCCESS after its NEWKEYS) and carries on (not in our OpenSSH alphabet, so not a harness class).
- 16:36 Catalogue witnesses on models of our servers are being replayed live with the harness that produced each model (`scripts_v2/verify_witnesses.py`).
- 16:45 Catalogue section written (`results/v2/A/harness_disagreements.md` Part 3).
  At the lead's finalise call these were still running and are left alone: catalogue witness live replay (`results/v2/A/catalogue_verified.json`, about 19 of 62 done, all CONFIRMED so far), the seeded Go re-learn, and the full-alphabet strict learns on all three servers.
  `results/v2/A/summary.md` was refused by the Write tool (subagent report-file rule); the summary text went to the lead in the final message.
- 16:50 Seeded Go re-learn (their --seeds with the 2 H5 words) finished: 11 states (was 9), 716 s; cross-diff vs B_gossh 8 classes (was 10): the 2 H5 classes are gone; their own refuted-witness loop fixes the model (`results/v2/A/xdiff_gossh_nonstrict_seeded.json`).
- 16:55 Catalogue witness live replay finished: 62/62 CONFIRMED, 0 REFUTED (`results/v2/A/catalogue_verified.json`; includes the not-applicable STRICT-KEX-* hits on non-strict models).
