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
