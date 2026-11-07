# CLAUDE.md

This file captures only what cannot be inferred from the codebase itself.
Add an entry when something surprises you; keep entries short, with the non-obvious *why*.

## Conventions

- Markdown uses semantic line breaks: one sentence per line, no hard wrapping.
- In auto mode, never commit; leave changes in the working tree for review.
- Mapper code is written by Codex (CLI, `codex exec`), not by Claude (team decision).
  Run it with `-s workspace-write -c sandbox_workspace_write.network_access=true --add-dir ~/.cache/uv`:
  the tests need the Docker socket, localhost ports and the uv cache. Bypassing the sandbox is not needed.
- Spawn agent CLIs (`codex exec`, `opencode run`) with `< /dev/null`: from a background shell stdin is an open pipe,
  and they wait for EOF on it before starting (opencode hung forever). Use `--json` so the log shows progress.

## Safety

- Targets run only as local containers published on 127.0.0.1.
  The repository is public: candidate vulnerabilities stay out of commits until the maintainers have been told.
