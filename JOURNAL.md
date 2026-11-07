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
- Team decision: publish CANDIDATE-001 now (spec ambiguity, not triggerable on-path); delegate source verification to Codex instead of a Claude subagent (the Claude subagent was stopped before writing anything).
- Codex verification (`findings/CANDIDATE-001-verification.md`, logs `logs/agents/codex-verify-candidate-001.*`): confirmed at high confidence;
  reset in the packet layer before dispatch, keys and cipher state unchanged, repeated stray NEWKEYS resets again; present since 1edb00c (2023-12-18) through V_10_6_P1 and master.
  Corrections adopted: version label (no upstream V_10_6_P2 tag), client terminates during auth, and conditional ChaCha20 replay acceptance once a misbehaving peer has sent the stray NEWKEYS. Severity: informational / low.
- 14:56 Team away for 30 min; authorised Nebius compute up to $20.
  Created VM `smlearn-vm` (`computeinstance-e04dgd6jmc1cp0nacr`, cpu-d3 32vcpu-128gb, 200 GiB SSD, Ubuntu 24.04), public IP 213.239.172.162.
  Cloud-init: key-only SSH, ufw allows only 22/tcp, Docker, uv, auto power-off after 6 h as a cost guard. Targets on the VM bind to 127.0.0.1 as everywhere.
  **Must be deleted when done** (`nebius compute instance delete --id computeinstance-e04dgd6jmc1cp0nacr`).
- Onboarding wave 1 spawned (one Codex agent each, `scripts/onboard.sh`, prompt template `agents/onboard-ssh-target.md`): paramiko, golang-xcrypto, erlang-otp, libssh.
  `tests/conftest.py` now takes `SMLEARN_TARGETS`; mapper sources added to `logs/protected.sha256`.
- VM ready; repo synced (no keys, no venv); on the VM 66 tests pass. Learning `v3vm` started there: openssh, dropbear, asyncssh, openssh-alpine-edge, 8 containers each (`scripts/learn_all.sh`).
  Local v3 stopped and archived (`results/runs/*-v3-local-aborted/`) to free the laptop for agent builds.
- Onboarding wave 1 results (Codex, one agent per target, reports in `targets/<name>/README.md` or `VALIDATION.md`):
  - erlang-otp (OTP 29.1.2, ssh 6.0.7): all tests pass.
  - golang-xcrypto (x/crypto v0.58.0) and libssh (0.12.2): all pass except rekey after auth.
    Both agents traced it to the mapper: these servers omit the strict-KEX marker in rekey KEXINITs (as the extension allows) but keep resetting sequence numbers, while the mapper re-evaluated strict mode on every server KEXINIT. **Mapper bug #2.**
  - paramiko (5.1.0): handshake fails; it only offers `curve25519-sha256@libssh.org`, the mapper only `curve25519-sha256`. **Mapper gap.**
  - All three agents stopped and reported instead of working around the failure, as instructed.
  Spec updated (strict KEX decided by the first KEXINIT and persistent; offer both curve25519 names); Codex fix 2 spawned (`logs/agents/codex-ssh-mapper-fix2.*`).
  These do not affect the v3 models of openssh/dropbear/asyncssh, which repeat the marker on rekey and offer `curve25519-sha256`.
- Onboarding wave 2 spawned: russh, wolfssh, mina-sshd, and erlang-otp-27.3.2 as a known-bug calibration control (CVE-2025-32433, fixed in 27.3.3).
- Codex fix 2 done: both curve25519 names offered; strict KEX fixed by the first server KEXINIT. Codex: 202 passed on 8 targets; Claude re-ran paramiko, golang-xcrypto, libssh: 46 passed, 3 skipped.
- Onboarding wave 2 (Codex): russh 0.65.1, wolfSSH 1.6.0 (wolfSSL 5.9.4), Apache MINA SSHD 2.20.1, Erlang/OTP 27.3.2 (ssh 5.2.9, calibration control): all 16 mapper tests pass on each.
  **12 implementations onboarded by agents, all passing the same validation suite.**
- OpenSSH 10.6 learning crashed on `closed during SSH identification`: OpenSSH ≥ 9.8 PerSourcePenalties throttles the learner's connection rate.
  Target config now disables PerSourcePenalties and raises MaxStartups; the learner retries failed connection setup with backoff and counts `reset_failures`.
- Stray-NEWKEYS experiment on all 12 targets (`results/seqnr/*.txt`), the first fully differential result:
  - reset receive counter, reply UNIMPLEMENTED, keep keys: OpenSSH 9.2p1 and 10.6p2 only (CANDIDATE-001);
  - disconnect: Dropbear, AsyncSSH, Paramiko, Go x/crypto, Erlang/OTP 29 and 27.3.2, wolfSSH, MINA SSHD;
  - silently ignore, keep counter: russh;
  - **no response to anything afterwards, connection left open: libssh 0.12.2** (candidate; Codex investigating, `logs/agents/codex-investigate-stray-newkeys.*`).
- Learning `v3vm` started on the VM for the 8 new targets (6 containers each).
- Codex investigation (`findings/CANDIDATE-002-libssh-stray-newkeys.md`, `scripts/stray_newkeys_followup.py`, `results/seqnr/*-followup.txt`):
  libssh 0.12.2 rejects the stray NEWKEYS in its packet filter and sets SSH_SESSION_STATE_ERROR without DISCONNECT or closing; later packets are dropped before decryption; keys untouched.
  Our target's event loop keeps polling (socket open ≥ 120 s, idle CPU); other connections unaffected. The open-socket part depends on the embedding application. Informational / low.
  russh: stray NEWKEYS outside KEX falls through to a no-op `_ => Ok(())` arm.
- First v3 model: OpenSSH 10.6p2 (`results/runs/openssh-alpine-edge-v3vm/`): 13 states, 9 rounds, 488 MQ + 2053 EQ, 870 s on 8 containers, 0 nondeterminism, 0 reset failures.
  Catalogue (`results/catalogue/openssh-alpine-edge-v3vm.json`): 13 ok, 2 violated, both known behaviours (calibration):
  CONN-BEFORE-AUTH (CH_OPEN before auth → UNIMPLEMENTED, as SPIN 2017 reported for OpenSSH 6.9) and REKEY-KEXINIT-REPLY (OpenSSH refuses pre-auth rekey, predicted in `literature/ssh-ground-truth.md`).
- v3 models finished on the VM so far: erlang-otp 12 states (770 s), golang-xcrypto 14 (1288 s), paramiko 14 (1174 s), wolfssh 16 (1161 s), openssh-alpine-edge 13 (870 s).
- Catalogue on those 5 found 8 violations. **Claude did not trust them**: the Go model reported CH_OPEN_SUCCESS without authentication after a pre-auth rekey (an auth bypass if real).
  Replay on the real container (`scripts/replay.py`) refuted it: the real server closes the connection. The learner had never queried that prefix (0 of 3614 queries) and merged "rekeyed, unauthenticated" with "authenticated".
  New step `src/smlearn/verify.py`: every catalogue witness is replayed 3× on a fresh container and marked CONFIRMED or REFUTED; refuted words are written as seeds for relearning.
  Result (`results/catalogue/verified-5.json`): 7 CONFIRMED, 1 REFUTED (the Go one).
  - OpenSSH 10.6: CONN-BEFORE-AUTH (UNIMPLEMENTED), REKEY-KEXINIT-REPLY (refuses pre-auth rekey): known.
  - Erlang/OTP 29: REKEY-KEXINIT-REPLY (disconnects on pre-auth rekey).
  - Paramiko 5.1.0: CONN-BEFORE-AUTH (CH_OPEN_FAILURE instead of disconnect), UA-BEFORE-SR-AUTH.
  - **wolfSSH 1.6.0: KEX-SERVER-SENDS-NON-KEX** — after its own rekey KEXINIT and before NEWKEYS it answers a user-auth request with USERAUTH_FAILURE (RFC 4253 §7.1 MUST NOT for the sender); also UA-BEFORE-SR-AUTH. Candidate, needs source verification.
  Learner: added a pre-auth-rekey seed path and `--seeds` (refuted witnesses as extra tests); Go relearn `golang-xcrypto-v4vm` started on the VM.
- Codex wolfSSH verification run was stopped by OpenAI's safeguard ("flagged for possible cybersecurity risk"), most likely by the prompt's request for attack/impact analysis (Terrapin, rogue session). Kept as `logs/agents/codex-verify-wolfssh.flagged.*`.
  Not circumvented: re-run as a narrower RFC-conformance task (reproduce, trace the dispatcher in source, conformance verdict only, no attack analysis): `logs/agents/codex-conformance-wolfssh.*`.
- Codex conformance run (not flagged): `findings/CANDIDATE-003-wolfssh-non-kex-during-rekey.md`.
  Confirmed RFC 4253 §7.1 MUST NOT violation: wolfSSH 1.6.0 sends USERAUTH_FAILURE between its rekey KEXINIT and NEWKEYS (also after a successful SERVICE_REQUEST); OpenSSH (refuses rekey) and Go (closes) do not.
  Root cause: `IsMessageAllowedServer` checks the keying state only for messages 1–49 (`src/internal.c:806–807`, v1.6.0-stable). Severity not assessed (attack analysis out of scope).
  Correction adopted: auth without SERVICE_REQUEST is behaviour, not a normative violation; the catalogue's SHOULD level for UA-BEFORE-SR-AUTH is a modelling choice (stated in README).
- More v3 models: openssh (9.2p1) 22 states, mina-sshd 21, russh 14. Verify (`results/catalogue/verified-batch2.json`): 6/6 CONFIRMED.
  OpenSSH: CH_CLOSE deferred until the client NEWKEYS during rekey (known, NDSS 2023), CONN-BEFORE-AUTH, REKEY-KEXINIT-REPLY (known). russh: CH_OPEN before auth silently ignored. MINA: CH_OPEN before auth → UNIMPLEMENTED.
  **MINA SSHD 2.20.1**: after auth, SERVICE_REQUEST(ssh-connection) is accepted and the open channel stops responding (CH_CLOSE unanswered, exec → CH_FAILURE; a new channel works). Replayed with controls; CANDIDATE-004, Codex conformance trace spawned (`logs/agents/codex-conformance-mina.*`).
- Team asked whether the wolfSSH finding is current. Built `targets/wolfssh-master` (master `d043c69`) and replayed side by side (`results/seqnr/wolfssh-release-vs-master.txt`):
  auth-without-service-request is **fixed on master** (`91cb9ad`, 2026-10-12, issue #1287, unreleased) — our pipeline independently rediscovered it;
  the RFC 4253 §7.1 violation is **still present on master** and broader: mid-rekey wolfSSH answers UA_SUCCESS and CH_OPEN_SUCCESS before its NEWKEYS.
  Same word on others: OpenSSH and MINA defer the reply until after NEWKEYS, Go and russh disconnect.
