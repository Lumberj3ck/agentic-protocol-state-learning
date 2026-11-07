# [Submission] <team name>: Agents build the mappers — two-harness differential state machine learning of SSH

<!-- Draft for the xemantic/claude-impact-lab-2026 "Project submission" issue form. Fill in team name and members before filing. -->

## Team name

<team name>

## Team members

<Name (@handle), role> — one per line

## Field

Other (network security / protocol verification)

## Repository

https://github.com/Lumberj3ck/agentic-protocol-state-learning

## License

Apache 2.0 for code, CC BY 4.0 for text

## Open problem

State machine learning finds protocol-implementation bugs by black-box measurement (TCP, TLS, SSH, DTLS, QUIC), but each study pays weeks of expert work per *mapper*, the adapter that turns abstract inputs into real, cryptographically correct packets.
That cost is why published studies cover 3–19 implementations.
The bug catalogue the models are checked against is also written by hand from the RFCs.
We asked: can agents build and validate the mapper and write the catalogue well enough to run differential learning across many more implementations?
It is checkable by computation: the handshake completes or not, repeated queries agree or not, and model disagreements and catalogue hits either replay on the real server or not.

## The research loop

Two arms of one experiment, merged in one repository (overview: `SYNTHESIS.md`):
the agent-built mapper (repository root) and the published-mapper harness (`reference-harness/`, full history of TheWingTheWong/proto-sm).
Cross-validation: on the same OpenSSH, Dropbear and Go servers the two harnesses had 0 server-level disagreements; of 32 learned-model disagreement classes the agent-built mapper was at fault in 2 (fixed by seeded relearning) and the published one in 26; 62 of 62 catalogue witnesses confirmed live on the published harness's models.

Agent-built arm:

1. **Literature:** Claude subagents turned RFC 4252–4254 and the strict-KEX draft into 15 bug patterns as automata, each with its quoted MUST/SHOULD (`literature/ssh-rfc-notes.md`, `catalogue/ssh/`), and collected what prior work predicts for our targets (`literature/ssh-ground-truth.md`).
2. **Test first:** Claude wrote the mapper contract and validation tests before any mapper code (`docs/MAPPER-SPEC-SSH.md`, `tests/test_ssh_mapper.py`).
3. **Mapper by an agent:** Codex (`codex exec`, sandboxed) implemented the SSH mapper from the RFCs, no SSH library (`src/smlearn/ssh/`, logs in `logs/agents/`); `logs/protected.sha256` checks it never edited tests or spec.
4. **Onboarding by agents:** one Codex agent per implementation writes the Docker target and must pass the same suite (`scripts/onboard.sh`, `agents/onboard-ssh-target.md`); 12 implementations, two waves of four in parallel.
5. **Learning:** AALpy KV with majority-vote nondeterminism checks and a parallel, protocol-seeded equivalence oracle, run on a 32-vCPU cloud VM (`src/smlearn/learn.py`, `scripts/learn_all.sh`).
6. **Self-checking:** every catalogue hit is replayed 3× on a fresh container and marked CONFIRMED or REFUTED (`src/smlearn/verify.py`); refuted hits go back to the learner as counterexamples. Candidate findings are traced in source by Codex.
7. **State in files:** `TASKS.md`, `JOURNAL.md` (every decision and result), `PROMPT.md` (continue in a new session).

## What the loop found

- **Two independent harnesses agree on every server behaviour they share** (`SYNTHESIS.md`, `reference-harness/results/v2/A/summary.md`); the published-mapper arm adds 39 verified divergences in 9 classes on OpenSSH 10.0p1, Dropbear 2025.88 and Go, validated against the original authors' published traces (`reference-harness/report.md`).

- **12 SSH implementations** onboarded by agents and passing one validation suite; 10 models learned and replay-verified (`results/SUMMARY.md`), 0 nondeterminism events.
- **Calibration:** reproduced the CCS 2025 Dropbear strict-KEX violation on our exact version; the Terrapin on/off control; 8 behaviours predicted by SPIN 2017 / NDSS 2023; the known-vulnerable Erlang/OTP 27.3.2 (CVE-2025-32433) is flagged blind while patched OTP 29 is not; wolfSSH's auth-before-service-request, which wolfSSH fixed upstream on 2026-10-12 (unreleased), was rediscovered independently.
- **CANDIDATE-003 (wolfSSH 1.6.0 and current master):** RFC 4253 §7.1 MUST NOT violation — during a key re-exchange the server sends USERAUTH_FAILURE/SUCCESS and CHANNEL_OPEN_CONFIRMATION before its NEWKEYS; OpenSSH and MINA defer, Go and russh disconnect. Source-traced. Conformance verdict; severity not assessed.
- **CANDIDATE-001 (OpenSSH 9.2p1 and 10.6):** under strict KEX, a stray NEWKEYS resets the receive sequence number while keys stay; root cause in `packet.c`, source-verified by Codex; informational/low (needs a misbehaving peer).
- **CANDIDATE-002 (libssh 0.12.2):** a stray NEWKEYS puts the session into a silent error state without DISCONNECT; informational/low.
- **CANDIDATE-004 (Apache MINA SSHD 2.20.1):** a post-auth SERVICE_REQUEST(ssh-connection) replaces the connection service and orphans open channels; their CHANNEL_CLOSE is never answered (RFC 4254 §5.3).
- **Differential:** a NEWKEYS outside a key exchange gets four different reactions across the 12 implementations (`results/seqnr/`).

Confidence: high for the behaviours (deterministic replays, source traces); the severity of all candidates is low or not assessed.

## Where it got stuck

- The first models were incomplete (uniform random equivalence testing never completes the handshake); fixed with protocol-seeded testing.
- Learned models are hypotheses: the catalogue reported an authentication bypass in Go x/crypto/ssh that replay refuted (two merged states); hence the mandatory replay step and counterexample feedback.
- Two catalogue patterns were too strict and were revised after replays (deferred strict-KEX termination).
- The loop found three bugs in its own mapper (key reuse after refused rekey, strict-KEX persistence, missing algorithm name); the agents stopped and reported each instead of working around it.
- Strict-KEX handshake conformance of 10 servers is already published (Bäumer et al., CCS 2025); our novelty is scale, the auth/connection/rekey layers, and implementations outside that set.
- OpenAI's safeguard stopped one Codex run that asked for attack analysis; it was re-run as conformance-only (both logs kept).
- AsyncSSH and Dropbear learn very slowly (auth-failure delays); the alphabet cannot express data on closed channels, unknown message IDs or client-sent USERAUTH_SUCCESS.

## What it would need next

More implementations (TinySSH needs public-key auth in the mapper; embedded/router builds), post-quantum hybrid KEX (`mlkem768x25519-sha256`) in the mapper, ChaCha20-Poly1305 to test CANDIDATE-001's cipher-dependent consequences, a second protocol (MQTT 5 or CoAP) through the same pipeline, and maintainer feedback on the candidates.

## How to run it

```shell
git clone https://github.com/Lumberj3ck/agentic-protocol-state-learning && cd agentic-protocol-state-learning
uv sync                                                    # Python 3.12+, Docker required
uv run pytest -q                                           # builds targets, validates the mapper
uv run python scripts/ground_truth_checks.py               # literature checks on real targets
uv run python -m smlearn.learn openssh --instances 4 --timeout 0.4 --quiet 0.1
uv run python -m smlearn.verify catalogue/ssh results/runs/wolfssh-v3vm/model.dot
uv run python scripts/replay.py wolfssh "KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK KEXINIT CH_OPEN" --trace
# agents: scripts/onboard.sh <name> "<implementation>" "<hints>"   (needs the Codex CLI)
```

## Data and sources

Public open-source implementations built from pinned releases (versions in `targets/*/target.json`); RFC 4251–4254, draft-miller-sshm-strict-kex-01, OpenSSH PROTOCOL; papers cited in `literature/`. No private data.

## How Claude was used

Claude Code (Opus) planned the loop, wrote specs, tests, the learner and analysis, reviewed every agent result and replayed every claim; Claude subagents read the RFCs and literature.
Codex CLI agents wrote the mapper, onboarded each implementation and traced candidates in source.
