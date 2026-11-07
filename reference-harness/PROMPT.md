# PROMPT (standing goal for any session)

By 17:00 on 2026-11-07, `report.md` answers, with evidence:
do independent open-source implementations of the SSH transport/auth handshake agree on their protocol state machine,
where do they disagree,
and for each disagreement which side follows RFC 4253/4252,
and is the disagreement a confirmed behavioural difference or an artifact of our test harness?
All tests pass.

Rules (from the user):
- Defensive conformance research on servers we run ourselves in Docker on the GX10 box. Never touch a host we do not control.
- All computation runs on the box via `./gx <cmd>` (runs in `~/research/proto-sm`; max 5 parallel jobs, 3 threads each, no GPU).
  `gx` was changed on 12:45 to use its own directory: the original pointed at `~/research/false-calm`, another live project.
- Targets: >=2 open-source SSH servers in Docker (OpenSSH, Dropbear, Go x/crypto/ssh), versions pinned and recorded.
- Method: active automata learning (AALpy) through a mapper from abstract symbols to real SSH bytes; diff learned models.
- Every disagreement must be REPLAYED as a concrete sequence against both servers, differing responses logged under `results/`.
  Disagreements that do not replay are discarded.
- A skeptical reviewer tries to prove each disagreement is a mapper bug before it is believed.
- Measure loop cost per implementation: mapper fixes, learning queries to converge, human corrections.
- State in files: TASKS.md (prioritized), JOURNAL.md (dated), this file. Tests before shared code. Commit as you go.
- Every claim in report.md points to a file in results/. State what the method cannot conclude.
- Freeze experiments 16:30, final verification, report.md done by 17:00.

## Architecture
- `psm/sshwire.py`: minimal SSH client protocol engine (packets, curve25519-sha256 KEX, aes128-ctr + hmac-sha2-256, ssh-ed25519 host keys).
- `psm/mapper.py`: AALpy `SUL`: abstract input symbol -> bytes, server packets -> abstract output symbol.
- `suts/<name>/`: Dockerfile + `run.sh` (build + start container `psm-<name>` on 127.0.0.1:<port>) + `VERSION.md`.
- `psm/learn.py`: learning driver; writes `results/models/<sut>__<config>.dot` and `results/learning/<sut>__<config>.json` (cost metrics).
- `psm/diff.py`: product-automaton diff of two Mealy machines -> distinguishing input sequences.
- `psm/replay.py`: replays sequences against live SUTs, logs to `results/replay/`.

## Shared conventions
- Ports on the box (127.0.0.1): openssh 2201, dropbear 2202, gossh 2203.
- Test account: user `tester`, password `correct-horse-battery`. Wrong password used by the mapper: `wrong-password`.
- Host key type: ssh-ed25519.

# v2 standing goal (from 2026-11-07 16:00; no deadline, depth and correctness over speed, but run in parallel)

Turn proto-sm into the strongest evidence on how SSH implementations differ, and on whether agent-built test harnesses can be trusted.
v1 = tag `submission-1700` (frozen 15:22 results): never edit or delete v1 files; new work goes in new files and report sections marked v2.

- A. Harness differential: compare our models with the teammate's independent agent-written harness (vendor/agentic-protocol-state-learning, Apache-2.0, read-only, never push) on the same implementations after mapping alphabets; adjudicate every harness disagreement by replay with both harnesses and a third independent client (stock paramiko). Run their RFC catalogue (catalogue/ssh/) on our models; feed our nine classes back as candidate catalogue patterns. Answer: how often do two independent harnesses disagree, and what does that say about trusting one?
- B. Scale and time: more current servers with our mapper (Erlang/OTP, AsyncSSH, russh, libssh, wolfSSH, Apache MINA, Paramiko server); version sweep OpenSSH 6.9p1..current and Dropbear ~2016..2025, finding the release where each D1-D9 appeared or changed. Pin every version and record how obtained. Servers that cannot negotiate the mapper's algorithms: log and move on.
- C. Close the gaps: strict KEX in the mapper; finish OpenSSH alphabet B; fix CH_MAX / channel inputs; re-learn where a fix changes the abstraction and show what changed.

Rules (v1 rules plus): only servers we run in Docker on 127.0.0.1 on the box; never contact another host. Docker: only psm-* containers/images, removed by ID, no box-wide prune; stop and log if free disk on / < 8 GB. At most 5 parallel box jobs, 3 threads each.
A finding exists only if it replays deterministically on the live servers and survives a skeptic subagent. Classify MUST / SHOULD / unspecified with the quoted RFC sentence; say "no security impact found" when so. Disclosure decisions stay with humans: write up, never send.

## v2 parallel layout (avoid collisions)
| Stream | Box job slots | SUT ports | mapper ports | container prefix | journal | mapper code |
|---|---|---|---|---|---|---|
| A harness differential | 1 | (uses existing 2201-2203, 2212, 2222) + 2401-2449 | 8401-8449 | psm-a- | journal/A.md | v1 (vendor/ssh-fuzzer) + teammate's |
| B1 new servers | 1 | 2301-2349 | 8301-8349 | psm-b1- | journal/B1.md | v1 |
| B2 version sweep | 1 | 2501-2599 | 8501-8599 | psm-b2- | journal/B2.md | v1 |
| C gaps | 2 | (uses existing SUTs) + 2601-2649 | 8601-8649 | psm-c- | journal/C.md | v2 copy: vendor/ssh-fuzzer-v2 |
The lead merges stream journals into JOURNAL.md, spawns skeptic reviewers, writes report v2 sections, and pushes.
