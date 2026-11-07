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
