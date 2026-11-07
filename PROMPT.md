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
