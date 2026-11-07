# JOURNAL

## 2026-11-07

- 12:44 Start. Repo empty except CLAUDE.md, gx, licenses.
- 12:45 Found `gx` hard-coded to sync into `~/research/false-calm` on the box, a different live project (own JOURNAL/TASKS/report).
  rsync would have overwritten its files. Changed `RDIR` to `${GX_RDIR:-research/proto-sm}`. CLAUDE.md's data paths refer to that other project and do not apply here; its compute rules do.
- 12:47 Box: aarch64, 20 cores, Docker usable without sudo, internet OK. venv `~/research/proto-sm/.venv`: AALpy 2.0.0, cryptography 50.0.2, pytest.
