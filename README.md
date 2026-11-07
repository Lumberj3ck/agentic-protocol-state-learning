# proto-sm: do SSH servers agree on the handshake state machine?

Active automata learning (AALpy) of OpenSSH 10.0p1, Dropbear 2025.88 and Go x/crypto/ssh 0.58.0 through the published SSH mapper of Fiterau-Brostean et al., model diffing, and replay of every disagreement.
Findings: `report.md`. Day log: `JOURNAL.md`.

All commands run from the repo root on the laptop; `./gx` executes them on the GX10 box (see `CLAUDE.md`).

## 0. One-time setup on the box

```bash
ssh gx10 'mkdir -p ~/research/proto-sm && cd ~/research/proto-sm && python3 -m venv .venv \
  && .venv/bin/pip install aalpy==2.0.0 cryptography pytest pydot paramiko'
# Throwaway RSA key for the learner (box only, gitignored; never the box user's ~/.ssh):
ssh gx10 'cd ~/research/proto-sm && mkdir -p keys && ssh-keygen -q -t rsa -b 3072 -m PEM -N "" -C psm-learner-test -f keys/id_rsa'
./gx .venv/bin/python -m pytest -q          # 30 tests
```

## 1. Build and start the servers (pinned; versions in `suts/*/VERSION.md`)

```bash
./gx bash suts/openssh/run.sh           # 127.0.0.1:2201
./gx bash suts/dropbear/run.sh          # 127.0.0.1:2202
./gx bash suts/gossh/run.sh             # 127.0.0.1:2203
./gx bash suts/dropbear-2020.81/run.sh  # 127.0.0.1:2212 (validation only)
./gx bash suts/dropbear-2022.83/run.sh  # 127.0.0.1:2222 (validation only)
```

Each script builds `psm-<name>:pinned`, restarts container `psm-<name>`, and installs the learner's test key (`suts/authorize.sh`).
Afterwards remove superseded `psm-*` images by ID; never prune box-wide.

## 2. Start mappers

The mapper is `vendor/ssh-fuzzer/ssh-mapper` (upstream commit in `vendor/ssh-fuzzer.COMMIT`, patches P1-P5 in `vendor/PATCHES.md`), run in container `psm-mapper-<name>` with the code mounted read-only.

```bash
# bash harness/start_mapper.sh <name> <listen_port> <sut_port> <timing_profile> <legacy|modern>
./gx bash -c 'bash harness/start_mapper.sh openssh  8001 2201 Dropbear modern; \
              bash harness/start_mapper.sh dropbear 8002 2202 Dropbear modern; \
              bash harness/start_mapper.sh gossh    8003 2203 Dropbear modern; \
              bash harness/start_mapper.sh db2020   8012 2212 Dropbear legacy'
```

All compared servers use the same timing profile (the published "Dropbear" one).
`legacy` is byte-identical upstream algorithm behaviour (DH group14-sha1, ssh-rsa); `modern` adds diffie-hellman-group14-sha256 and rsa-sha2-256 for current servers.
One mapper serves one client at a time: start extra instances (other ports) for concurrent learners.

## 3. Learn

```bash
A=KEXINIT,KEX30,NEWKEYS,SR_AUTH,UA_PK_OK          # published alphabet
B=$A,SR_CONN,CH_OPEN                              # + pre-auth gates
./gx bash -c "(PYTHONUNBUFFERED=1 nohup .venv/bin/python -m psm.learn --name A_dropbear --port 8002 \
    --alphabet $A --oracle rekey --walks-per-state 25 --max-len 10 > results/learning/A_dropbear.log 2>&1 &)"
```

Output: `results/models/<name>.dot`, `results/learning/<name>/{stats.json,cache.json,nondet.jsonl,harness_errors.jsonl}`.
`--cache-in <cache.json>` reuses answers from an earlier run against the same server and mapper settings.
Nondeterminism is detected by repeating queries and logged in `nondet.jsonl` (majority vote; never silently used).

## 4. Diff, replay, verify

```bash
./gx bash -c '.venv/bin/python -m psm.diff results/models/A_openssh.dot results/models/A_dropbear.dot results/models/A_gossh.dot \
      --names openssh dropbear gossh --normalize reference/normalize.json --out results/diff/A_threeway.json; \
  .venv/bin/python -m psm.diff_to_seqs results/diff/A_threeway.json --out results/diff/A_threeway_seqs.json; \
  .venv/bin/python -m psm.replay --target openssh=8001:psm-openssh --target dropbear=8002:psm-dropbear \
      --target gossh=8003:psm-gossh --reps 5 --seq-file results/diff/A_threeway_seqs.json --out results/replay/A_threeway_replay.json; \
  .venv/bin/python -m psm.verify results/replay/A_threeway_replay.json --normalize reference/normalize.json --out results/final/verified_A'
```

- `psm.diff`: product-automaton BFS; shortest distinguishing sequence per disagreement class (`--inputs` restricts to a sub-alphabet).
- `psm.replay`: replays each sequence N times per server, storing every observation and the server container's log.
- `psm.verify`: keeps only deterministic, non-tainted (`psm/taint.py`) disagreements; writes `.json` and a `.md` table.
- `psm.check_traces <model.dot> <replay.json>[:target]`: does a model predict replayed traces?
- `psm.costs`: research-loop cost table (`results/loopcost_table.md`); needs `results/loopcost.jsonl` copied to the box (`scp results/loopcost.jsonl gx10:research/proto-sm/results/`).

## Validation against published results

```bash
./gx .venv/bin/python -m psm.replay --target dropbear2020=8012:psm-dropbear2020 --reps 3 \
  --seq "KEXINIT KEX30 NEWKEYS UA_PK_OK" --out results/replay/check.json   # expect ... UA_SUCCESS (NDSS 2023)
./gx .venv/bin/python -m psm.diff results/models/dropbear2022.dot reference/published_dropbear2022.83_hyp5.dot \
  --out results/diff/check.json
```

`reference/published_dropbear2022.83_hyp5.dot` is the published ssh-fuzzer model (`vendor/ssh-fuzzer/ssh-learner/output/DROPBEAR_SERVER_1683485573153/learnedModel.dot`) with LearnLib labels `in / out` rewritten to AALpy's `in/out`.

## Layout

| Path | What |
|---|---|
| `suts/` | pinned server images, run scripts, VERSION.md |
| `vendor/ssh-fuzzer/` | published mapper (and learner inputs/outputs) at a pinned commit; `vendor/PATCHES.md` |
| `harness/` | mapper image and launcher |
| `psm/` | learner bridge, robust SUL, oracles, diff, replay, taint, verify, costs |
| `tests/` | pytest suite (fake mapper speaking the real line protocol) |
| `reference/` | inputs the box must read (published model, normalisation map) |
| `results/` | everything produced: models, learning stats, diffs, replays, checks, reviews, final tables |
| `notes/literature.md` | prior work and RFC clauses |
