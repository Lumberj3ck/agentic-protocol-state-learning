Created `targets/russh/` with russh **0.65.1**, pinned in Cargo.toml and Cargo.lock, a minimal server, and a multi-stage Dockerfile.

Validation: **16 passed, 1 skipped** (OpenSSH-only test). No blocking behavior differences or known mapper failures occurred.

[Per-test results and source references](targets/russh/README.md). Docker required a writable `DOCKER_CONFIG` under `/tmp`. All repository edits stayed under `targets/russh/`.