# Session prompt

Start a new session with: `continue the goal described in PROMPT.md`.

## Goal

Agents build and validate protocol mappers and an RFC-derived bug catalogue,
well enough to run differential state machine learning across many more implementations
than hand-written mappers allow.
First protocol: SSH.
Done for the hackathon when at least three SSH implementations have learned models,
every pairwise disagreement and every catalogue violation has a witness replayed on the real target,
and the results are written up with their limits.

## How to work

- Take the top open task in `TASKS.md`; update it when done.
- Append every result and decision to `JOURNAL.md`, with links.
- Test first: write the check, then the code.
- Mapper code is written by Codex:
  `codex exec -m gpt-6.1-sol -s workspace-write -c sandbox_workspace_write.network_access=true --add-dir ~/.cache/uv --json -o <last.md> "<task>" < /dev/null`.
  Claude writes specs and tests, then verifies.
  After a Codex run, check `sha256sum -c logs/protected.sha256` (tests and spec unchanged).
- Other atomic steps (catalogue drafting, onboarding a target) run in their own subagent.
- Targets only as local containers on 127.0.0.1. Never probe hosts we don't run.
- Possible new bugs: record in `findings/` as *candidate*, confirm by replay on the real target,
  and keep details out of public commits until the maintainers are told.
- Do not commit; leave changes for the team to review.
- Ask the team before needing more compute (Nebius VM available).

## Commands

```shell
uv run pytest -q                                   # all tests (Docker needed for mapper tests)
uv run python -m smlearn.learn openssh --instances 4
uv run python -m smlearn.diff results/*/model.dot --coarse
uv run python -m smlearn.catalogue catalogue/ssh results/*/model.dot
```
