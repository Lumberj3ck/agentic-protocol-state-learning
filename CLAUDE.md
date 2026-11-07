# CLAUDE.md

Do independent SSH server implementations (OpenSSH, Dropbear, Go x/crypto/ssh) agree on the transport/auth state machine?
We learn each server's state machine with AALpy through the published ssh-fuzzer mapper, diff the models, and replay every disagreement as a concrete sequence.
Standing goal and rules: `PROMPT.md`. Plan: `TASKS.md`. Dated log: `JOURNAL.md`. Write-up: `report.md`.

## Where code runs

- This laptop has 8 GB of RAM. Never run Python, learning or replays locally.
- Run everything on the GX10 box through `./gx <command>`, e.g. `./gx .venv/bin/python -m pytest -q`.
  It syncs the code up, runs the command in `~/research/proto-sm` on the box (override with `GX_RDIR`), and syncs `results/` back.
- Write every output (models, diffs, replays, reviews, logs) under `results/`: nothing else comes back from the box.
- The box is shared with other people: at most 5 parallel jobs, 3 CPU threads each, no GPU.

## Safety and the shared box

- Defensive conformance research only, against servers we run ourselves in Docker on the box, bound to 127.0.0.1. Never contact any other host.
- Docker: only touch containers and images named `psm-*`, and remove images by ID. Never `docker system prune`, `docker builder prune` or anything box-wide.
- If free disk on `/` drops below 8 GB, stop and log it in `JOURNAL.md`.
- The learner's throwaway test key lives in `keys/` on the box only (gitignored). Never use the box user's `~/.ssh`.

## Layout

- `suts/<name>/`: Dockerfile + `run.sh` (build and start `psm-<name>`) + `VERSION.md` (pinned version).
  Ports (127.0.0.1): OpenSSH 10.0p1 2201, Dropbear 2025.88 2202, Go x/crypto 0.58.0 2203, Dropbear 2020.81 2212, Dropbear 2022.83 2222.
  `suts/authorize.sh <container>` installs `keys/id_rsa.pub` for user `tester`.
- `vendor/ssh-fuzzer/`: the published mapper (MIT), with our five small patches documented in `vendor/PATCHES.md`. We wrote no SSH protocol or crypto code.
- `harness/start_mapper.sh <name> <listen_port> <sut_port> <timing> [legacy|modern]`: one mapper container `psm-mapper-<name>` per learner or replay target.
  Current servers use timing `Dropbear` and `modern` (same settings for every compared server).
- `psm/`: `learn.py` (L* driver), `robust_sul.py` (cache + nondeterminism checks), `oracles.py` (rekey-aware equivalence), `diff.py`, `diff_to_seqs.py`, `replay.py`, `verify.py`, `taint.py`, `check_traces.py`, `costs.py`.
- `reference/`: published Dropbear 2022.83 model and `normalize.json` (documented extension messages set aside before diffing).
- `results/`: `models/`, `learning/`, `diff/`, `replay/`, `review/`, `checks/`, `final/`, `loopcost_table.md`.

## Reproduce

1. On the box, once: `python3 -m venv .venv && .venv/bin/pip install aalpy==2.0.0 paramiko==5.1.0 pydot==4.0.1 pytest==9.2.0`, and create a throwaway RSA key with `ssh-keygen -t rsa -N '' -f keys/id_rsa`.
2. Start the servers: `./gx bash suts/openssh/run.sh` (same for `dropbear`, `gossh`).
3. Start a mapper per server: `./gx bash harness/start_mapper.sh openssh 8001 2201 Dropbear modern` (and 8002/2202, 8003/2203).
4. Learn: `./gx .venv/bin/python -m psm.learn --name A_openssh --port 8001 --alphabet KEXINIT,KEX30,NEWKEYS,SR_AUTH,UA_PK_OK --oracle rekey`.
5. Diff: `./gx .venv/bin/python -m psm.diff results/models/A_dropbear.dot results/models/A_gossh.dot --out results/diff/x.json --normalize reference/normalize.json`.
6. Turn the diff into sequences with `psm.diff_to_seqs`, replay them on all servers with `psm.replay --target openssh=8001:psm-openssh ...`, and classify with `psm.verify`.

## Rules for claims

- A disagreement counts only if it replays as a concrete sequence on the live servers, repeatably; the model alone is not evidence.
- A skeptical reviewer tries to explain each one as a mapper artifact before it is believed (`results/review/`).
- Every claim in `report.md` points to a file in `results/`. Say what the method cannot conclude.
- Run the tests (`./gx .venv/bin/python -m pytest -q`) before relying on changed shared code.

## Markdown

Use semantic line breaks: one sentence per line.
