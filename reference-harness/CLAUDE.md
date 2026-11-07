# CLAUDE.md

SSH protocol state-machine learning: do independent SSH servers (OpenSSH, Dropbear, Go x/crypto/ssh) agree on the RFC 4253/4252 handshake?
Goal and rules: `PROMPT.md`. Current state: `TASKS.md`, `JOURNAL.md`. How to reproduce: `README.md`.

## Where code runs

- This laptop has 8 GB of RAM. Never run Python, Docker or learning locally, not even a one-off `python3` to read JSON (use `jq`).
- Run every computation on the GX10 box through `./gx <command>`, e.g. `./gx .venv/bin/python -m pytest -q`.
  It syncs the code up (everything except `.git`, `.venv`, `data/`, `results/`), runs the command in `~/research/proto-sm` on the box, and syncs `results/` back.
  `gx` originally pointed at `~/research/false-calm`, another live project; never point it there (override only via `GX_RDIR`).
- Write every output (models, replays, diffs, reviews, logs) under `results/`: nothing else comes back from the box.
  `gx` does not upload `results/`, so inputs the box must read (e.g. the published model, `normalize.json`) live in `reference/`.
- The box is shared with other people: at most 5 parallel jobs, 3 CPU threads each (`./gx` sets `OMP_NUM_THREADS=3`). No GPU.
  Long jobs: start them with `nohup ... &` inside `./gx bash -c '...'`, log to `results/learning/<name>.log`.
  Never use `pkill -f` with a pattern that also matches your own shell; use `pgrep -f "[p]attern"`.

## Disk and Docker on the shared box

- The box disk is ~99% full. Pin small images.
- After building, `docker rmi` only OUR superseded `psm-*` images and base images we pulled. Never prune box-wide (`docker system/builder/image prune`): it deletes other people's data.
- Touch only containers named `psm-*`.

## Network and targets

- Defensive conformance research on servers we run ourselves. Containers bind to 127.0.0.1 on the box only. Never contact a host we do not control.
- SUT ports: OpenSSH 2201, Dropbear 2202, Go 2203, Dropbear 2020.81 2212, Dropbear 2022.83 2222.
- Mapper ports: replay/review mappers 8001-8003; learning mappers 81xx; old-version mappers 8012/8022.
  A mapper serves one client at a time: give each concurrent learner or replay its own mapper instance.

## Integrity

- We do not write SSH protocol or crypto code. The mapper is the published one (`vendor/ssh-fuzzer`, pinned commit); every change is a numbered patch in `vendor/PATCHES.md`.
- A disagreement is reported only if it is replayed against all servers (`psm/replay.py`), deterministic, not harness-tainted (`psm/verify.py`, `psm/taint.py`), and survived a skeptical review (`results/review/`).
- The throwaway learner key lives only in `keys/` on the box (gitignored). Never use the box user's `~/.ssh`.

## Markdown

Use semantic line breaks: one sentence per line.
