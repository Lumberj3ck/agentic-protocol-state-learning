### Team name

Plov

### Team members

Alan Yuldashev (@Lumberj3ck), engineer, agent-built-mapper arm (repository root), submission lead
Ansorjon Juraev (@TheWingTheWong), engineer, published-mapper arm (`reference-harness/`, merged with full history from TheWingTheWong/proto-sm)

### Field

Other

### Repository

https://github.com/Lumberj3ck/agentic-protocol-state-learning

### License

Apache 2.0 for code, CC BY 4.0 for text (the bundled ssh-fuzzer mapper in `reference-harness/vendor/` is MIT)

### Open problem

State machine learning finds protocol-implementation bugs by black-box measurement (TCP, TLS, SSH, DTLS, QUIC), but every study pays weeks of expert work per *mapper*, the adapter that turns abstract inputs into real, cryptographically correct packets.
That cost is why published studies cover 3–19 implementations, and the bug catalogue the models are checked against is also written by hand from the RFCs.
Question: can agents build and validate the mapper and the catalogue well enough to run differential learning across many more implementations, and can the result be trusted?
It is checkable by computation: the handshake completes or not, repeated queries agree or not, and every model disagreement or catalogue hit either replays on the real server or not.

### The research loop

We ran both arms of the experiment and merged them in one repository; overview in `SYNTHESIS.md`.

**Agent-built arm (repository root):**
1. Literature: Claude subagents turned RFC 4252–4254 and the strict-KEX draft into 15 bug patterns as automata, each with its quoted MUST/SHOULD (`literature/ssh-rfc-notes.md`, `catalogue/ssh/`), and collected what prior work predicts for our targets (`literature/ssh-ground-truth.md`).
2. Test first: Claude wrote the mapper contract and validation tests before any mapper code (`docs/MAPPER-SPEC-SSH.md`, `tests/test_ssh_mapper.py`).
3. Codex (`codex exec`, sandboxed) implemented the SSH mapper from the RFCs with no SSH library (`src/smlearn/ssh/`, prompts and logs in `logs/agents/`); `logs/protected.sha256` checks it never edited tests or spec.
4. One Codex agent per implementation writes the Docker target and must pass the same suite (`scripts/onboard.sh`, `agents/onboard-ssh-target.md`): 12 implementations in two parallel waves.
5. Learning: AALpy KV, majority-vote nondeterminism checks, protocol-seeded parallel equivalence oracle, on a 32-vCPU cloud VM (`src/smlearn/learn.py`, `scripts/learn_all.sh`).
6. Self-checking: every catalogue hit is replayed 3× on a fresh container and marked CONFIRMED or REFUTED (`src/smlearn/verify.py`); refuted witnesses are fed back to the learner as seeds; candidates are traced in source by Codex (`findings/`).
7. State in files: `TASKS.md`, `JOURNAL.md`, `PROMPT.md`; results table `results/SUMMARY.md` (`scripts/summarize.py`).

**Published-mapper arm (`reference-harness/`):** reuses Fiterau-Brostean et al.'s ssh-fuzzer mapper with 5 documented patches, validates it against the original authors' published traces symbol for symbol, learns OpenSSH 10.0p1, Dropbear 2025.88 and Go x/crypto 0.58.0, replays every divergence on all servers, and runs skeptic-review subagents (`reference-harness/report.md`, `reference-harness/psm/`).

**Cross-validation:** each arm's harness was run on the other's servers and its models compared (`reference-harness/results/v2/A/summary.md`, `reference-harness/psm/xharness.py`).

### What the loop found

- **Two independent harnesses, 0 server-level disagreements** on OpenSSH, Dropbear and Go; of 32 learned-model disagreement classes, the agent-built mapper was at fault in 2 (a Go state merge, fixed by seeded relearning) and the published mapper in 26 (its documented limits); 62 of 62 catalogue witnesses confirmed live on the published harness's models (`SYNTHESIS.md`).
- **12 SSH implementations** passing one validation suite (8 onboarded by one Codex agent each, 4 set up by Claude); 10 models learned; 23 catalogue hits, 19 confirmed and 4 refuted by replay (`results/SUMMARY.md`).
- **Published-mapper arm:** 39 verified divergence points in 9 classes (D1–D9) between OpenSSH, Dropbear and Go; Dropbear's NDSS 2023 and OpenSSH's SPIN 2017 findings unchanged in 2025 releases (`reference-harness/report.md`).
- **Calibration:** CCS 2025 Dropbear strict-KEX violation reproduced on our exact version; Terrapin on/off control; known-vulnerable Erlang/OTP 27.3.2 (CVE-2025-32433) flagged blind while patched OTP 29 is not; wolfSSH's auth-before-service-request, fixed upstream on 2026-10-12 (unreleased), rediscovered independently.
- **CANDIDATE-003, wolfSSH 1.6.0 and current master:** RFC 4253 §7.1 MUST NOT violation: during a key re-exchange the server sends USERAUTH_FAILURE/SUCCESS and CHANNEL_OPEN_CONFIRMATION before its NEWKEYS; OpenSSH and MINA defer, Go and russh disconnect; source-traced (`findings/CANDIDATE-003-wolfssh-non-kex-during-rekey.md`). Conformance verdict; severity not assessed.
- **CANDIDATE-001, OpenSSH 9.2p1 and 10.6:** under strict KEX a stray NEWKEYS resets the receive sequence number while keys stay; root cause in `packet.c`; informational/low (needs a misbehaving peer).
- **CANDIDATE-002, libssh 0.12.2:** a stray NEWKEYS puts the session into a silent error state without DISCONNECT; informational/low.
- **CANDIDATE-004, Apache MINA SSHD 2.20.1:** a post-auth SERVICE_REQUEST(ssh-connection) replaces the connection service and orphans open channels, whose CHANNEL_CLOSE is never answered (RFC 4254 §5.3).
- **Differential:** a NEWKEYS outside a key exchange gets four different reactions across the 12 implementations (`results/seqnr/`).

Confidence: high for the behaviours (deterministic replays, two harnesses, source traces); severity of all candidates low or not assessed.

### Where it got stuck

- First models were incomplete: uniform random equivalence testing never completes the handshake; fixed with protocol-seeded testing. Both arms produced plausible but wrong models and caught them only by replay.
- The catalogue reported an authentication bypass in Go x/crypto/ssh that replay refuted (two merged states); hence the mandatory replay step and counterexample feedback.
- Two catalogue patterns were too strict and were revised after replays (strict-KEX termination may be deferred until NEWKEYS).
- The loop found three bugs in its own mapper (key reuse after a refused rekey, strict-KEX persistence, a missing algorithm name); agents stopped and reported each instead of working around it.
- Dropbear and AsyncSSH accept unlimited channels, so their models never converged; the one-channel bound (`CH_MAX`, as in SPIN 2017) is specified but not implemented (`TASKS.md`).
- Strict-KEX handshake conformance of 10 servers is already published (Bäumer et al., CCS 2025); our novelty is the agent-built mapper at scale, the auth/connection/rekey layers, and implementations outside that set.
- OpenAI's safeguard stopped one Codex run that asked for attack analysis; it was re-run as conformance-only (both logs kept).

### What it would need next

The one-channel bound and relearning of Dropbear and AsyncSSH; public-key auth (TinySSH) and post-quantum hybrid KEX (`mlkem768x25519-sha256`) in the agent-built mapper; ChaCha20-Poly1305 to test CANDIDATE-001's cipher-dependent consequences; a second protocol (MQTT 5 or CoAP) through the same pipeline; maintainer feedback on the candidates.

### How to run it

```shell
git clone https://github.com/Lumberj3ck/agentic-protocol-state-learning && cd agentic-protocol-state-learning
uv sync                                                    # Python 3.12+, Docker required
uv run pytest -q                                           # builds targets, validates the mapper
uv run python scripts/ground_truth_checks.py               # literature checks on real targets
uv run python -m smlearn.learn openssh --instances 4 --timeout 0.4 --quiet 0.1
uv run python -m smlearn.verify catalogue/ssh results/runs/wolfssh-v3vm/model.dot
uv run python scripts/replay.py wolfssh "KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK KEXINIT CH_OPEN" --trace
# agents: scripts/onboard.sh <name> "<implementation>" "<hints>"   (needs the Codex CLI)
# published-mapper arm: see reference-harness/README.md
```

### Data and sources

Public open-source implementations built from pinned releases (`targets/*/target.json`, `reference-harness/suts/*/VERSION.md`); RFC 4251–4254, draft-miller-sshm-strict-kex-01, OpenSSH PROTOCOL; ssh-fuzzer (MIT); papers cited in `literature/` and `reference-harness/notes/literature.md`. No private data.

### How Claude was used

Claude Code (Opus) planned both loops, wrote specs, tests, learners and analysis, reviewed every agent result and replayed every claim; Claude subagents read the RFCs and literature and acted as skeptic reviewers.
In the agent-built arm, Codex CLI agents wrote the mapper, onboarded each implementation and traced candidates in source.

### Demo materials

`SYNTHESIS.md` and `README.md` in the repository.

### Confirmations

- [X] The repository is public and has an open-source license.
- [X] The submission contains no secrets, API keys or non-anonymized private data.
- [X] We agree that this submission text is published under CC BY 4.0, like the other written material in this repository.
