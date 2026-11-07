# Journal

Every result, decision and exchange with the team, with links to the outputs.

## 2026-11-07

- Read the hackathon requirements (README, RESEARCH-LOOPS.md, submission template, judge-submissions skill).
  Rubric: Problem, Loop, Evidence, Honesty, Reproducibility; Apache 2.0 + CC BY 4.0.
- Decision: Python + AALpy (no Java on the machine, so no LearnLib).
- Decision: all targets run as local Docker containers published on 127.0.0.1 only.
  Any new bug is disclosed privately to maintainers before it goes into this public repository.
- Decision (team): mapper implementations are written by Codex in opencode (`openai/gpt-5.6-sol`);
  Claude writes the spec and the validation tests, and verifies.
  Codex runs with a scoped `opencode.json` (file edits, pytest and read-only commands only)
  rather than `--auto`.
- First opencode run hung at startup for 12 min (waiting for EOF on stdin); restarted with `< /dev/null`.
- Team switched mapper agent to the Codex CLI (`codex exec`, `gpt-6.1-sol`, workspace-write sandbox).
  opencode run stopped before it wrote any code; protected files verified unchanged.
- Decision (team): build on the laptop first; ask before moving to the Nebius VM for scale.
- Built targets: `targets/openssh` (Debian bookworm), `targets/dropbear` (Alpine 3.20), `targets/asyncssh` (2.17.0).
- Wrote [mapper spec](docs/MAPPER-SPEC-SSH.md) and [validation tests](tests/test_ssh_mapper.py) before any mapper code.
- Wrote learner (`src/smlearn/learn.py`: KV algorithm, majority vote on nondeterminism, parallel equivalence oracle),
  differential analysis (`src/smlearn/diff.py`) and bug-pattern checker (`src/smlearn/catalogue.py`),
  with offline tests in `tests/test_analysis.py` (4 pass).
- Removed two stray test files (`tests/test_mapper.py`, `tests/test_wire.py`) left by an interrupted earlier turn;
  they targeted a different module layout.
- Catalogue subagent finished: 15 patterns (strict KEX ×3, KEX ordering, service/auth/connection layering, DISCONNECT, rekey, channel close),
  each with the quoted normative sentence and MUST/SHOULD level; 59 offline tests pass (verified by re-running).
  Not expressible with the current alphabet: data on a closed channel, order of messages inside one step, sequence-number reset (only visible as BAD_PACKET).
  Note: strict KEX is OpenSSH PROTOCOL §1.9 (V_9_6_P1) and draft-miller-sshm-strict-kex-01; the mapper spec wrongly says §1.10.
- Codex (`gpt-6.1-sol`) wrote the mapper: `src/smlearn/ssh/{wire,packet,mapper}.py` (~320 lines) + `tests/test_ssh_wire.py` (10 offline tests).
  Log: `logs/agents/codex-ssh-mapper.jsonl`, report: `logs/agents/codex-ssh-mapper.last.md`.
  It stopped instead of editing the tests: AsyncSSH sends an empty IGNORE before SERVICE_ACCEPT and CH_OPEN_SUCCESS,
  and two happy-path assertions demanded exact outputs. The spec (report every message) was right; Claude relaxed those two assertions to token membership.
  Result: 112 tests pass (`uv run pytest -q`), mapper tests green on openssh, dropbear, asyncssh; protected files unchanged by Codex.
- First implementation difference observed: AsyncSSH 2.17.0 interleaves SSH_MSG_IGNORE with replies after key exchange; OpenSSH and Dropbear do not.
- Timing check (`scripts/timing_check.py 0.4 0.1 5`): 0/9 words nondeterministic on each target at timeout 0.4 s, quiet 0.1 s; ~80 ms per step.
- Started learning all three targets in parallel (3 containers each, full 17-symbol alphabet, timeout 0.4, quiet 0.1).
- Learning v1 finished (archived in `results/runs/*-v1-random-eq/`): openssh 8 states, asyncssh 6, dropbear 3, 0 nondeterminism events.
  **Rejected as incomplete**: the Dropbear model sends `KEXINIT KEX30` back to the initial state and misses everything after key exchange.
  Cause: the equivalence oracle used uniform random suffixes, which almost never complete the 5-step handshake out of 17 inputs.
  Fix: seed the oracle with protocol paths (handshake+exec, rekey after auth, failed auth, double channel open);
  every prefix of each path is extended with every single input and with random suffixes; answers are cached across rounds.
  Test: `tests/test_analysis.py::test_eq_oracle_covers_seed_paths_depth_one`.
- Learning v2 started: 5 containers per target (15 total), seeded oracle.
- Ground-truth subagent: `literature/ssh-ground-truth.md` (30 findings from SPIN 2017, Verleg 2016, NDSS 2023, Terrapin, CCS 2025, advisories).
  **Important for novelty**: Bäumer, Maehren, Brinkmann, Schwenk, "Finding SSH Strict Key Exchange Violations by State Learning", CCS 2025 (arXiv 2509.10895, verified)
  already state-learned the strict-KEX *handshake* of 10 servers. Our contribution must be elsewhere:
  agent-built mappers at scale, the auth/connection/rekey layers, implementations outside their set, PQ hybrid KEX.
- Ground-truth replay (`scripts/ground_truth_checks.py` → `results/ground-truth/checks.json`): 12 words × 3 targets × strict on/off × 3 runs, all deterministic.
  - Reproduced CCS 2025's Dropbear finding on our exact version (2024.85): IGNORE/DEBUG/UNIMPLEMENTED accepted after the server's NEWKEYS and before the client's under strict KEX; OpenSSH and AsyncSSH disconnect.
  - Control: with strict KEX on all three disconnect on an injected IGNORE; with it off all three tolerate it (Terrapin precondition).
  - Matched predictions: Dropbear auth without SR_AUTH; OpenSSH UNIMPLEMENTED for SR/UA after auth and for CH_OPEN before auth; Dropbear SERVICE_ACCEPT after auth; AsyncSSH disconnect; OpenSSH refuses pre-auth rekey, Dropbear allows it; OpenSSH defers CH_CLOSE to the client NEWKEYS during rekey (NDSS 2023).
  - Candidate (low severity, not in any paper we found): AsyncSSH 2.17.0 accepts USERAUTH_REQUEST without a prior SERVICE_REQUEST(ssh-userauth) and then opens a channel. Correct password still required. Same class as Dropbear's documented wontfix.
  - **Mapper bug found by the replay**: after a refused rekey, NEWKEYS re-installed the old pending keys (AES-CTR keystream restart + strict-KEX seq reset), so OpenSSH saw a MAC failure (`CLOSED`). Artifact of the mapper, not the server.
    Learning v2 aborted (archived in `results/runs/*-v2-aborted-key-reuse/`). Spec clarified (per-direction pending keys, consumed on install), failing test `test_newkeys_without_new_kex_keeps_keys` added, Codex spawned for the fix (`logs/agents/codex-ssh-mapper-fix1.*`).
- Codex fix 1 (`logs/agents/codex-ssh-mapper-fix1.*`): pending keys per direction, consumed on install; sequence reset only when keys are installed; 14 offline tests.
  The OpenSSH regression test still failed, and Codex stopped, reporting from sshd debug output that OpenSSH resets its receive sequence number on the rejected NEWKEYS.
  Claude confirmed with `scripts/seqnr_experiment.py`: under strict KEX, OpenSSH 9.2p1 answers a stray NEWKEYS with UNIMPLEMENTED, keeps its keys, and resets its receive counter (variant A fails, B without strict KEX and C with a client-side reset succeed). Dropbear and AsyncSSH disconnect instead.
  So the mapper was right and the test encoded a wrong assumption; the test now validates the mapper with strict KEX off. All tests pass.
  Recorded as `findings/CANDIDATE-001` (spec ambiguity in strict KEX §3.3; low severity as far as we can tell; `findings/` git-ignored pending a disclosure decision).
- CANDIDATE-001 also reproduces on current OpenSSH 10.6p2 (new target `targets/openssh-alpine-edge`).
  Root cause located in upstream `packet.c` (receive path resets `p_read.seqnr` for any NEWKEYS under `kex_strict`, before dispatch rejects it).
- Learning v3 started with the fixed mapper (4 containers per target).
