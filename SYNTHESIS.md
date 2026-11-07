# Two harnesses, one question

Can agents build the mapper for protocol state machine learning, instead of experts spending weeks per implementation?
The team ran both arms of that experiment on the same day, with independent code bases, agents and authors:

| | Agent-built mapper (this repository) | Published mapper ([`reference-harness/`](reference-harness/), Ansorjon Juraev) |
|---|---|---|
| Mapper | Written by Codex from the RFCs against tests written first; no SSH library | Fiterau-Brostean et al.'s ssh-fuzzer (Paramiko-based, SPIN 2017 / NDSS 2023) with 5 small patches |
| Key exchange, auth | curve25519-sha256, password, strict KEX by default | DH group14, public key, non-strict |
| Learner | AALpy KV, protocol-seeded parallel oracle, 32-vCPU VM | AALpy L*, state-prefix + rekey oracle |
| Breadth | 12 implementations (8 onboarded by one Codex agent each, 4 set up by Claude); 10 models | 3 servers (+ Dropbear 2020.81/2022.83 for validation); 18-version replay sweep |
| Ground truth | Literature predictions replayed; CCS 2025 Dropbear finding, Erlang CVE-2025-32433 control | Original authors' published traces replayed symbol for symbol |
| Checks | Every catalogue hit replayed (`src/smlearn/verify.py`) | Every divergence replayed on all servers + skeptic-review subagents |
| Output | RFC catalogue (15 patterns), 4 candidate findings | 39 divergence points in 9 classes (D1–D9) |

## Cross-validation (reference-harness `results/v2/A/summary.md`)

Both harnesses were run on the same OpenSSH 10.0p1, Dropbear 2025.88 and Go x/crypto 0.58.0 containers.

- **0 server-level disagreements**: the two harnesses never disagreed about what a server did with the same bytes; all 120 replay pairs that start with KEXINIT agree at every step.
- **32 learned-model disagreement classes**, each replayed live with both mappers and attributed: the agent-built mapper was wrong in **2** (the Go model merged states across a pre-auth rekey, also found here by `verify.py` and fixed by relearning with the refuted witness as a seed; the 2 classes disappear), the published mapper in **26** (its documented limits: a close reported one step late, stream corruption after a stray NEWKEYS, a one-channel cap), and 4 are setup differences.
- **This repository's RFC catalogue on the published harness's models**: 62 of 62 witnesses confirmed live; it picks out the same implementations as the hand-written D1–D9 classes.
- Every D1–D9 class is reproduced by the agent-built harness; with strict KEX on, D7 and the initial-KEX part of D9 disappear, as predicted.

## The same findings, found independently

| Published-mapper class | Agent-built mapper result |
|---|---|
| D1: Dropbear authenticates without a SERVICE_REQUEST (NDSS 2023, still in 2025.88) | `UA-BEFORE-SR-AUTH` on Dropbear, Paramiko, libssh, wolfSSH 1.6.0 (fixed on wolfSSH master 2026-10-12) |
| D2: OpenSSH answers a pre-auth CHANNEL_OPEN with UNIMPLEMENTED | `CONN-BEFORE-AUTH` on OpenSSH 9.2p1 and 10.6p2 |
| D3: OpenSSH refuses a client rekey before authentication (SPIN 2017) | `REKEY-KEXINIT-REPLY` on OpenSSH, Erlang/OTP, libssh |
| D5: service requests after authentication | [CANDIDATE-004](findings/CANDIDATE-004-mina-sshd-service-request-after-auth.md): MINA SSHD orphans open channels |
| D9 + the "stray NEWKEYS corrupts the stream" taint filter | [CANDIDATE-001](findings/CANDIDATE-001-openssh-seqnr-reset-on-stray-newkeys.md) and [-002](findings/CANDIDATE-002-libssh-stray-newkeys.md): OpenSSH resets its receive counter, libssh goes silent; four behaviours across 12 implementations |

Only the agent-built arm reached [CANDIDATE-003](findings/CANDIDATE-003-wolfssh-non-kex-during-rekey.md) (wolfSSH, RFC 4253 §7.1, still on master), because only it covered wolfSSH with a learned model.

## What the comparison says

- An agent-built mapper, validated by tests written first and by replay, reproduced the published mapper's server-level observations exactly, and carried fewer harness errors into its models on these servers.
- Both arms produced plausible but wrong models from weak equivalence oracles, and both caught them only by replaying on the live server; a second, independent harness is a cheap way to find harness bugs, but it does not replace replay.
- The published mapper bought validation against the original authors' traces; the agent-built mapper bought breadth (12 implementations, strict KEX, curve25519) at the cost of three mapper bugs found and fixed during the day.
- Limits: one host, one version per implementation in the cross-check, 7 shared inputs; both harnesses come from the same field knowledge (RFCs and SPIN/NDSS work), so "independent" means different authors, code, agents, key exchange and auth, not a different method.
