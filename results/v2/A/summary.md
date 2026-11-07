# Stream A summary: how often do two independently built harnesses disagree?

Written by the stream-A agent; saved by the lead, with the corrections from the code review (`notes/code_review_v2.md`, findings 3 and 4) applied.
Evidence: `results/v2/A/harness_disagreements.md`; journal `journal/A.md`.

Harnesses: ours (published ssh-fuzzer Paramiko mapper + P1-P5, DH group14, publickey, non-strict, AALpy L*) and the teammate's (Codex-written RFC mapper, curve25519, password, strict by default, AALpy KV), both run on our OpenSSH 10.0p1, Dropbear 2025.88 and Go x/crypto 0.58.0 containers.
Vocabulary map: `results/v2/A/alphabet_map.json`.

## Numbers

- **Replay of all 64 v1 sequences through their mapper** (3 servers, 3 reps, non-strict): 192 pairs, 127 agree, 65 disagree, 0 nondeterministic.
  All 120 pairs that start with KEXINIT agree at every step; all 65 disagreements start with another input.
  - H1, our mapper's automatic KEXINIT: 40 pairs, setup difference (the two harnesses send different messages).
  - H2, a server close in the same step as its KEXINIT, which our output reports one step late: 25 pairs, **ours wrong** (known abstraction limit). Reclassified from "setup" after the code review: the third client shows the server closes immediately.
  - Theirs wrong: 0.
  - Strict KEX on: 72 mismatching pairs in total (not 73), the extra ones all strict-KEX setup differences; Dropbear `KEX30 KEXINIT` agrees only under strict KEX.
- **Learned models** (their learner on our servers vs our v1 models, non-strict): 294 product transitions compared, 244 agree (83%); 32 disagreement classes, each replayed live with both mappers (3 reps, all deterministic).
  - Ours wrong: 26 classes (11 H2 hidden close, 11 NEWKEYS stream corruption, 4 one-channel cap). All three are documented limitations of our mapper; v1 reported no finding affected by them (taint filter, first-divergence rule).
  - Setup difference: 4 classes (H1 automatic KEXINIT).
  - Theirs wrong: 2 classes (their Go model merges states across a pre-auth rekey; their mapper agrees with ours on the live server).
  - Strict: 27 classes, the same mechanisms plus strict-KEX ones.
- **Server-level disagreements between the harnesses: 0.**
  Every v1 class D1-D9 is reproduced by the second harness; with strict KEX, D7 and the initial-KEX part of D9 go away, as v1 predicted.
- **Catalogue**: on the shared alphabet, their 15 patterns and our D1-D9 (`catalogue-v2/`) pick out the same implementations on our models and on theirs.
  Their reported hits for OpenSSH (CONN-BEFORE-AUTH, REKEY-KEXINIT-REPLY) and Dropbear (UA-BEFORE-SR-AUTH) are reproduced on our versions; Go has none.
  Live witness replay: 25 of 62 done, all confirmed; the rest unchecked.

## What it says about trusting one harness

- The two harnesses never disagreed about what a server did with the same bytes.
  Every disagreement traced to how a harness builds messages, how it summarises replies, its configuration (strict KEX, ext-info), or one learned model the equivalence oracle did not separate.
- Each harness alone carried errors that a model diff would show as findings: ours 26 classes, theirs 2.
  A second harness surfaced all of them in one pass, and a third client settled each one.
- So: trust a single harness's replayed, filtered sequences, not its raw models.
  A second independent harness is a cheap and effective way to find harness bugs (28 of 32 model classes were one harness's fault), but it does not replace replay on the live server: in the Go case the model was wrong while both mappers were right.

## Limits

- One version per implementation, 3 servers, one host; 7 shared inputs (5 for OpenSSH). Not a rate estimate for other protocols or alphabets.
- Part 1 replays sequences our harness chose, so it measures replication, not coverage; Part 2 is bounded by both equivalence oracles.
- Both harnesses were built from the same field knowledge (RFCs, published SSH learning work): "independent" means a different author, code base, agent, key exchange and auth method, not a different method.
- The third client matches each harness's message order but uses its own key exchange method (code review finding 7).
- Unchecked: seeded Go re-learn; full-alphabet strict models; remaining catalogue witnesses; witnesses on their other targets.
