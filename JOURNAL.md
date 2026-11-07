# JOURNAL

## 2026-11-07

- 12:44 Start. Repo empty except CLAUDE.md, gx, licenses.
- 12:45 Found `gx` hard-coded to sync into `~/research/false-calm` on the box, a different live project (own JOURNAL/TASKS/report).
  rsync would have overwritten its files. Changed `RDIR` to `${GX_RDIR:-research/proto-sm}`. CLAUDE.md's data paths refer to that other project and do not apply here; its compute rules do.
- 12:47 Box: aarch64, 20 cores, Docker usable without sudo, internet OK. venv `~/research/proto-sm/.venv`: AALpy 2.0.0, cryptography 50.0.2, pytest.
- 2026-11-07: suts/openssh built (OpenSSH 10.0_p1-r11, Alpine 3.22), running psm-openssh on 127.0.0.1:2201; verified password login, wrong-password rejection, strict-kex offered.
2026-11-07: suts/dropbear built and verified (dropbear 2025.88-r1 on alpine:3.22 pinned by digest, 127.0.0.1:2202).
- 12:50 Mapper (raw SSH client engine, `psm/sshwire.py`) write was stopped partway; the partial file was removed. Mapper work is paused pending the user's decision. SUT containers (OpenSSH 10.0p1, Dropbear 2025.88) and `psm/diff.py` (11 tests pass) are done.
