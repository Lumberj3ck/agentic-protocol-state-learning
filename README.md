# Agent-built mappers for differential state machine learning

A research loop for the [Claude Impact Lab Berlin 2026](https://github.com/xemantic/claude-impact-lab-2026).

**Question:** can agents build and validate the *mapper* (the protocol adapter between a learning algorithm and a real implementation),
and write the bug catalogue from the RFCs,
well enough to run differential state machine learning across many more implementations than hand-written mappers allow?

State machine learning of network protocols is mature (TCP, TLS, SSH, DTLS, QUIC),
but every study pays weeks of expert work per mapper,
which is why studies cover 3–19 implementations.
The checks that make this a good fit for an agent loop are mechanical:
the handshake completes against the real server or not,
repeated queries give the same answer or not,
and learned models of different implementations agree or show a disagreement that can be replayed.

First protocol: **SSH**.

## How the loop works

| Step | Who | Where |
|---|---|---|
| Read the RFCs and the strict-KEX draft, write a bug catalogue as automata, with quoted MUST/SHOULD sentences | Claude subagent | [`literature/ssh-rfc-notes.md`](literature/ssh-rfc-notes.md), [`catalogue/ssh/`](catalogue/ssh/) |
| Read prior model-learning work, predict what our targets should show | Claude subagent | [`literature/ssh-ground-truth.md`](literature/ssh-ground-truth.md) |
| Write the mapper contract and validation tests *before* any mapper code | Claude | [`docs/MAPPER-SPEC-SSH.md`](docs/MAPPER-SPEC-SSH.md), [`tests/test_ssh_mapper.py`](tests/test_ssh_mapper.py) |
| Implement the mapper from the RFCs (no SSH library) until the tests pass on real servers | Codex (`codex exec`, sandboxed) | [`src/smlearn/ssh/`](src/smlearn/ssh/), logs in [`logs/agents/`](logs/agents/) |
| Check the agent did not touch tests or spec | script | [`logs/protected.sha256`](logs/protected.sha256) |
| Run targets as local Docker containers, many in parallel | testbed | [`targets/`](targets/), [`src/smlearn/testbed.py`](src/smlearn/testbed.py) |
| Learn Mealy machines (AALpy KV), measure nondeterminism, parallel equivalence testing seeded with protocol paths | learner | [`src/smlearn/learn.py`](src/smlearn/learn.py) |
| Compare models pairwise, check them against the catalogue, replay every witness on the real target | analysis | [`src/smlearn/diff.py`](src/smlearn/diff.py), [`src/smlearn/catalogue.py`](src/smlearn/catalogue.py), [`scripts/`](scripts/) |

State lives in files: [`TASKS.md`](TASKS.md) (prioritized queue),
[`JOURNAL.md`](JOURNAL.md) (every result and decision),
[`PROMPT.md`](PROMPT.md) (lets a new session continue the goal).

## What it found so far

- **Mapper:** written by Codex in ~320 lines, passes 120+ tests on OpenSSH 9.2p1, Dropbear 2024.85 and AsyncSSH 2.17.0, deterministic at 0.4 s timeouts.
  Twice the agent *stopped instead of editing a test* and reported a real behaviour that contradicted the test
  (AsyncSSH interleaving IGNORE packets; OpenSSH's sequence-number reset below).
- **Ground truth reproduced** ([`results/ground-truth/checks.json`](results/ground-truth/checks.json), [`scripts/ground_truth_checks.py`](scripts/ground_truth_checks.py)):
  the CCS 2025 Dropbear strict-KEX late-window violation on our exact version;
  the strict-KEX on/off control (Terrapin precondition) on all three;
  and 8 further predicted behaviours from SPIN 2017 / NDSS 2023 / source reading.
- **Mapper bug caught by the loop:** a refused rekey re-installed old keys; found by the ground-truth replay, fixed by Codex against a failing test.
- **Candidate finding** ([`findings/CANDIDATE-001`](findings/CANDIDATE-001-openssh-seqnr-reset-on-stray-newkeys.md)):
  under strict KEX, OpenSSH (9.2p1 and current 10.6p2) resets its receive sequence number on a NEWKEYS received outside a key exchange,
  while rejecting it with UNIMPLEMENTED and keeping its keys; Dropbear and AsyncSSH disconnect.
  Root cause in upstream `packet.c`.
  We assess it as a spec ambiguity in the strict-KEX draft, not an exploitable vulnerability; verification in progress.
- **Low-severity deviation:** AsyncSSH 2.17.0 authenticates and opens a channel without a prior `ssh-userauth` service request (Dropbear does the same, documented as intended).

## Where it got stuck

- The first learned models were incomplete (Dropbear: 3 states): uniform random equivalence testing never completes the handshake.
  Fixed by seeding the oracle with protocol paths; see [`JOURNAL.md`](JOURNAL.md).
- Strict-KEX handshake conformance of 10 servers is already published (Bäumer et al., CCS 2025, arXiv 2509.10895);
  our novelty has to come from scale, the auth/connection/rekey layers, implementations outside that set, and post-quantum KEX.
- The alphabet cannot express data on a closed channel, unknown message numbers, or a client-sent USERAUTH_SUCCESS (see [`literature/ssh-rfc-notes.md`](literature/ssh-rfc-notes.md)).

## How to run

Needs Docker, [uv](https://docs.astral.sh/uv/) and Python 3.12+.
Targets bind to 127.0.0.1 only.

```shell
uv sync
uv run pytest -q                                          # builds and starts the targets
uv run python scripts/ground_truth_checks.py              # literature checks on real targets
uv run python scripts/seqnr_experiment.py openssh         # CANDIDATE-001
uv run python -m smlearn.learn openssh --instances 4 --timeout 0.4 --quiet 0.1
uv run python -m smlearn.diff results/*/model.dot --coarse
uv run python -m smlearn.catalogue catalogue/ssh results/*/model.dot
```

The mapper agent: `codex exec -s workspace-write -c sandbox_workspace_write.network_access=true --add-dir ~/.cache/uv "<prompt>" < /dev/null`,
prompts in [`logs/agents/*.prompt.md`](logs/agents/).

## License

Code: [Apache 2.0](LICENSE). Text: [CC BY 4.0](LICENSE-CC-BY-4.0).
