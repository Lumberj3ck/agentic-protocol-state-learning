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

Before trusting anything on current releases, we checked the harness against what the original authors published.

1. The published finding reproduces on the version they analysed.
   On Dropbear 2020.81, `KEXINIT KEX30 NEWKEYS UA_PK_OK` gives `KEXINIT KEX31+NEWKEYS+EXT_INFO NO_RESP UA_SUCCESS`: authentication succeeds without any SERVICE_REQUEST, the NDSS 2023 "Missing SERVICE_REQUEST_USERAUTH" finding (`results/replay/smoke_dropbear2020.json`).
2. All four counterexample traces recorded by the original authors (`vendor/ssh-fuzzer/ssh-learner/output/DROPBEAR_SERVER_1683485573153/statistics.txt`) replay symbol for symbol, 3 of 3 repetitions (`results/replay/published_cex_dropbear2020.json`).
3. Our first learned model was wrong on one of those published traces (`results/checks/dropbear2020_v1.json`): it merged "authenticated, then rekeyed" with "not yet authenticated".
   The cause was our equivalence oracle (random words), not the mapper; with walks from every state the model grows from 7 to 9 states and predicts all 8 replayed traces (`results/checks/dropbear2020_v2.json`).
   This is the main methodological lesson: the mapper reproduced the published behaviour immediately, while the equivalence check is where an under-learned model hides.
4. Our 2020.81 model and the published (unfinished; the run timed out after 12 h) 2022.83 model differ on only 2 transitions, both after a first message of KEX30 (`results/diff/dropbear2020_vs_published2022.json`); our side of both replays 5 of 5 on 2020.81 (`results/replay/dropbear2020_vs_published_diffs.json`).
   VERSION-OR-GAP: TODO (Dropbear 2022.83 learning run).

## Results

TODO

## What the method cannot conclude

- **An unlearned transition is not proof of absence.**
  A learned model is only as good as the equivalence check.
  Ours twice produced plausible, wrong models (Dropbear v1, Go with state-prefix walks) that a deeper test exposed (`results/checks/dropbear2020_v1.json`; JOURNAL 13:21, 13:29).
  "Server X has no state where Y happens" means only "we did not find one with these tests".
  Every behavioural claim in this report therefore rests on a replayed concrete sequence, not on the model alone.
- **The alphabet bounds the conclusions.**
  We learned 5 inputs (the published alphabet) and 7 with SR_CONN and CH_OPEN.
  No other message types, no malformed fields, no strict KEX (the published mapper never offers `kex-strict-c-v00@openssh.com`), no ext-info, no keyboard-interactive, one key exchange method (`diffie-hellman-group14-sha256`, which OpenSSH 10.0 only offers because we re-enabled it).
  The Terrapin-era strict-KEX rules are therefore untested here.
- **The abstraction hides some behaviour.**
  The mapper reports all messages that arrive within 0.35 s as one symbol, drops server IGNORE/DEBUG, does not show a TCP close that happens in the same step as a message, and caps channels at one (`CH_MAX` is a mapper-made symbol).
  DISCONNECT reason codes are not part of the output.
- **Configuration matters.**
  We changed only what the mapper needed (RSA host key, one DH group in OpenSSH, `PerSourcePenalties no`); other defaults (MaxAuthTries, LoginGraceTime) were not varied.
- **One version per implementation** for the current-release comparison, and one host (localhost, low latency); timing-dependent behaviour under load was not studied.

## Cost of the research loop, and what an agent can automate

TODO
