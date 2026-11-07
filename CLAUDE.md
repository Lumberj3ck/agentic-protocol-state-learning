# CLAUDE.md

## Where code runs

- This laptop has 8 GB of RAM. Never run Python, pandas or model training locally.
- Run every computation on the GX10 box through `./gx <command>`, e.g. `./gx .venv/bin/python -m pytest -q`.
  It syncs the code up, runs the command in `~/research/false-calm` on the box, and syncs `results/` back.
- Write every output (figures, tables, metrics, logs) under `results/`: nothing else comes back from the box.
- The data lives only on the box, in `data/raw/Collision Avoidance Challenge - Dataset/kelvins_competition_data/`
  (`train_data.csv`, `test_data.csv`, `test_data_private.csv`). Read the path from `DATA_DIR` with that as the default, so the code also runs on any laptop with the data downloaded.
- The box is shared with other people: at most 5 parallel jobs, 3 CPU threads each (`./gx` sets `OMP_NUM_THREADS=3`; pass `n_jobs=3` / `num_threads=3` explicitly). No GPU.

## Integrity

- Only `evaluate.py` may read `test_data_private.csv`, and it runs once, at the end.

## Markdown

Use semantic line breaks: one sentence per line.
