# Do independent SSH servers agree on the transport/auth state machine?

Status: DRAFT (results sections are filled as evidence lands; see JOURNAL.md).

## Question

Do independent open-source implementations of the SSH transport (RFC 4253) and user-authentication (RFC 4252) handshake agree on their protocol state machine?
Where they disagree, which side follows the RFCs, and is the disagreement a confirmed behavioural difference or an artifact of our test harness?

## Setup

All servers ran in Docker on the GX10 box, bound to 127.0.0.1 only; nothing outside the box was contacted.

| SUT | Version | Pinning | Notes |
|---|---|---|---|
| OpenSSH | 10.0p1 (`SSH-2.0-OpenSSH_10.0`) | Alpine 3.22 `openssh-server=10.0_p1-r11`, base digest in `suts/openssh/VERSION.md` | `PerSourcePenalties no`; RSA host key and `KexAlgorithms +diffie-hellman-group14-sha256` added for the mapper |
| Dropbear | 2025.88 (`SSH-2.0-dropbear_2025.88`) | Alpine 3.22 `dropbear=2025.88-r1` | RSA host key added |
| Go x/crypto/ssh | v0.58.0 (`SSH-2.0-Go`), Go 1.26.0 | `suts/gossh/go.mod` + `go.sum` | minimal server in `suts/gossh/main.go`; RSA host key added |
| Dropbear (validation only) | 2020.81 | Alpine 3.13 `dropbear=2020.81-r0` | the version analysed in NDSS 2023 |

## Method

We build on the published method rather than from scratch (`notes/literature.md`).
de Ruiter & Poll (USENIX Sec 2015) learned TLS state machines with a mapper and LearnLib and treated model differences as leads to be checked by hand.
Fiterau-Brostean et al. (SPIN 2017; NDSS 2023) did the same for SSH with a mapper built on a heavily modified Paramiko.
We reuse that mapper unmodified except for three small patches (`vendor/PATCHES.md`): an opt-in algorithm profile for current servers, credentials from the environment, and a crash fix when the learner disconnects.
We wrote no SSH protocol or crypto code ourselves.

- Learner: AALpy 2.0.0 L* (`psm/learn.py`) talking to the mapper's line protocol (`psm/mapper_client.py`).
- Abstraction (the published one): one input symbol per client message; the output is the `+`-joined names of all server messages received in a fixed window, `NO_RESP` if none, `NO_CONN` once the TCP connection is closed (a sink). The mapper drops server `IGNORE`/`DEBUG`.
- Identical mapper settings for every compared SUT (published "Dropbear" timing profile: 0.3 s first-response / 0.35 s total window, 0.25 s between inputs).
- Nondeterminism: every query is checked against a prefix cache; any conflict, and a random 10% of fresh queries, are re-run and decided by majority, and every event is logged (`results/learning/<sut>/nondet.jsonl`), so it cannot silently corrupt a model (`psm/robust_sul.py`).
- Equivalence: random walks from every learned state (AALpy `StatePrefixEqOracle`).
- Diff: product-automaton BFS for shortest distinguishing sequences (`psm/diff.py`).
- Evidence: every reported disagreement is replayed as a concrete sequence against all servers, repeated, with each observation and the server's own log stored under `results/replay/` (`psm/replay.py`).
- A skeptical reviewer subagent tries to explain each disagreement as a harness artifact before we accept it (`results/review/`).

## Validation: reproducing published results first

TODO

## Results

TODO

## What the method cannot conclude

TODO

## Cost of the research loop, and what an agent can automate

TODO
