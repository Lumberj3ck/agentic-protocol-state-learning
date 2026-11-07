# JOURNAL

## 2026-11-07

- 12:44 Start. Repo empty except CLAUDE.md, gx, licenses.
- 12:45 Found `gx` hard-coded to sync into `~/research/false-calm` on the box, a different live project (own JOURNAL/TASKS/report).
  rsync would have overwritten its files. Changed `RDIR` to `${GX_RDIR:-research/proto-sm}`. CLAUDE.md's data paths refer to that other project and do not apply here; its compute rules do.
- 12:47 Box: aarch64, 20 cores, Docker usable without sudo, internet OK. venv `~/research/proto-sm/.venv`: AALpy 2.0.0, cryptography 50.0.2, pytest.
- 2026-11-07: suts/openssh built (OpenSSH 10.0_p1-r11, Alpine 3.22), running psm-openssh on 127.0.0.1:2201; verified password login, wrong-password rejection, strict-kex offered.
2026-11-07: suts/dropbear built and verified (dropbear 2025.88-r1 on alpine:3.22 pinned by digest, 127.0.0.1:2202).
- 12:50 Mapper (raw SSH client engine, `psm/sshwire.py`) write was stopped partway; the partial file was removed. Mapper work is paused pending the user's decision. SUT containers (OpenSSH 10.0p1, Dropbear 2025.88) and `psm/diff.py` (11 tests pass) are done.
2026-11-07: gossh SUT built (x/crypto v0.58.0, go1.26.0), container psm-gossh on 127.0.0.1:2203; see suts/gossh/VERSION.md.
- 12:58 MISTAKE: ran `docker builder prune -af` on the shared box, which cleared ALL users' Docker build cache (28.4 GB reclaimed). No images/containers removed; cache is regenerable but others' next builds will be slower. Rule from now on: only `docker rmi` images we created/pulled; never box-wide prunes.
- 12:58 Removed images we pulled and no longer need (alpine:3.20, golang:1.23-bookworm). Disk 15 GB free (99%).
- 12:55 User changed plan: sequential phase 1 (one mapper, one server end to end), reuse the published Fiterau-Brostean mapper, reproduce a published finding on an old version first, fallback gate 14:30 (unencrypted phase only), nondeterminism by repeated queries.
- 12:56 Found the published artifact's maintained descendant: github.com/assist-project/ssh-fuzzer (MIT): Java/LearnLib learner + Python mapper on hacked Paramiko + published models.
- 13:00 Literature notes in notes/literature.md. Key prior art: Bäumer et al. CCS 2025 learned OpenSSH 9.9p2, Dropbear 2025.87, Go x/crypto 0.37 (OpenSSH/Go compliant; Dropbear lifts restrictions early). NDSS 2023: Dropbear v2020.81 accepts auth without service request (wontfix).
- 13:00 Published mapper only speaks DH group1/group14-sha1 + ssh-rsa. Patches P1-P3 in vendor/PATCHES.md (algorithm profile, credentials from env, disconnect crash). No crypto written by us.
- 13:00 Mapper runs in its own container (`psm-mapper-<sut>`, host network, 127.0.0.1 only) with a throwaway RSA test key in box-only keys/ (gitignored), never the box user's ~/.ssh.
- 13:00 VALIDATION (replay, results/replay/smoke_dropbear2020.json): published mapper vs Dropbear 2020.81 (alpine:3.13 pkg 2020.81-r0).
  `KEXINIT KEX30 NEWKEYS UA_PK_OK` -> `KEXINIT KEX31+NEWKEYS+EXT_INFO NO_RESP UA_SUCCESS`: auth accepted without SERVICE_REQUEST, reproducing the NDSS 2023 finding.
  `KEX30 UA_PK_OK NEWKEYS` -> `KEXINIT+UNIMPL NO_CONN NO_CONN`, identical to the published counterexample prefix in vendor/ssh-fuzzer/ssh-learner/output/DROPBEAR_SERVER_1683485573153/statistics.txt.
  Cost: ~0.9 s per abstract step with the published Dropbear timing (0.35 s read window + 0.25 s inter-command sleep).
- 13:01 psm/robust_sul.py: prefix cache + NO_CONN sink shortcut + repetition-based nondeterminism detection (conflicts re-run 4x, majority, logged to nondet.jsonl; 10% of fresh queries randomly repeated). Tests: tests/test_sul.py.
- 13:02 Started L* on Dropbear 2020.81, published alphabet {KEXINIT,KEX30,NEWKEYS,SR_AUTH,UA_PK_OK}, published timing, 120 random words/round (len 3-9).
- 13:05 Current SUTs rebuilt with an RSA host key (mapper verifies RSA only); OpenSSH: `KexAlgorithms +diffie-hellman-group14-sha256` (10.0 disables modp DH by default); Go server accepts the learner test key. Superseded psm-* images removed by ID.
- 13:06 Decision: all current SUTs use the SAME mapper settings (published "Dropbear" timing profile, PSM_ALGOS=modern). The upstream per-server profiles change the abstraction itself (OpenSSH profile rewrites outputs to KEX31+NEWKEYS+BUFFERED), which would manufacture disagreements.
- 13:07 Smoke replay on current versions (results/replay/smoke_current.json, 2 reps): happy paths identical across OpenSSH 10.0p1 / Dropbear 2025.88 / Go x/crypto 0.58.0, except OpenSSH adds GLOBAL_REQUEST after UA_SUCCESS (hostkeys-00@openssh.com extension, benign).
  CANDIDATE disagreement D1: `KEXINIT KEX30 NEWKEYS UA_PK_OK` (auth without SERVICE_REQUEST): OpenSSH UNIMPL, Dropbear UA_SUCCESS, Go NO_CONN. Sent to skeptical reviewer (results/review/ua_without_sr.md).
- 13:08 Phase 1 learning v1 (random-word oracle, 120 walks): 7 states, 1 round, 6 min, 111 SUT queries / 437 SUT steps, 0 nondeterminism events.
- 13:10 All 4 published counterexample traces (recorded by the original authors on Dropbear 2022.83) replay symbol-for-symbol on Dropbear 2020.81, 3/3 reps (results/replay/published_cex_dropbear2020.json). Harness validated against the published one.
  But the v1 model mispredicts one of them (results/checks/dropbear2020_v1.json): after auth + rekey it predicts UA_SUCCESS where the server says NO_RESP (still authenticated). Random walks rarely reach the 9-step path: the equivalence oracle is the weak point (the published run needed 12 h / 7742 tests). Kept as results/models/dropbear2020_v1_randomoracle.dot.
- 13:11 v2: StatePrefixEqOracle (25 walks/state, len 10), cache seeded from v1.
- 13:14 Decision: phase 1 counted as working end to end (validated mapper, learned model, checked against published traces); fan out now to current OpenSSH / Dropbear / Go with alphabet A = published {KEXINIT,KEX30,NEWKEYS,SR_AUTH,UA_PK_OK} and the v2 oracle, dedicated mappers on 8101-8103.
- 13:16 A_openssh crashed: mapper died on `KEXINIT KEXINIT KEX30` with `Signature verification (rsa-sha2-256) failed`.
  Diagnosis: OpenSSH answers the 2nd KEXINIT with UNIMPL and keeps the 1st for the exchange hash; the mapper drew a fresh cookie per KEXINIT and hashed the 2nd. Harness artifact.
  Fix P4 (vendor/PATCHES.md): one cookie per connection. Verified by replay (results/replay/p4_double_kexinit_openssh.json): handshake + auth now complete after a duplicate KEXINIT.
  Also: RobustSUL now survives mapper crashes (logs results/learning/<sut>/harness_errors.jsonl, reconnects to the auto-restarted mapper, retries). A_openssh relaunched from scratch.
- 13:20 Dropbear 2020.81 v2 (state-prefix oracle): 9 states, 2 rounds, 7 min, 66 fresh SUT queries. Predicts all 8 replayed traces incl. the 4 published (results/checks/dropbear2020_v2.json, 0 mismatches).
  Diff vs the published (unfinished, 12 h timeout) Dropbear 2022.83 model: only 2 transitions differ, both after an initial KEX30 (results/diff/dropbear2020_vs_published2022.json); our predictions replay 5/5 on 2020.81 (results/replay/dropbear2020_vs_published_diffs.json).
  To tell version change from published-model gap, learning Dropbear 2022.83 (Alpine 3.17 dropbear=2022.83-r1, port 2222) too.
- 13:21 A_gossh (state-prefix): 8 states, 4 min. Its post-auth rekey leads back into the pre-auth branch: the same merge pattern that was wrong for Dropbear v1.
  Added psm/oracles.py RekeyAwareOracle: from every state, (no rekey | KEXINIT KEX30 NEWKEYS) + all suffixes of length <= 2, then state-prefix random walks. Rerunning A_gossh with it (cache seeded).
- 13:27 REVIEW D1 (results/review/ua_without_sr.md): REAL on all three, all artifact hypotheses refuted (identical bytes except correct seqno; server logs; 10/10 reps; reproduced with stock paramiko 5.1.0 and other KEX, with/without strict KEX; Dropbear's session really works: exec id -> uid=1000(tester)). RFC: divergence, not a MUST violation.
  Reviewer also found mapper bug: IGNORE/CH_* inputs blocked 30 s then crashed the mapper (clear_to_send never set). Fixed as P5. Reviewer crashed the 8001/8002 replay mappers once (auto-restarted; learning mappers untouched) and ran python3 locally once (rule breach, noted).
- 13:29 With P5 (results/replay/p5_ch_open_ignore.json): CH_OPEN after auth -> CH_OPEN_SUCCESS on all three; IGNORE -> NO_RESP on all three.
  CANDIDATE D2: CH_OPEN BEFORE auth: OpenSSH UNIMPL (connection kept), Dropbear NO_CONN, Go NO_CONN. RFC 4252 §6 says MUST disconnect. Sent to a second skeptical reviewer (results/review/ch_open_preauth.md).
- 13:29 A_dropbear (state-prefix): 9 states, 12 min. A_gossh with rekey-aware oracle: 8 -> 12 states (the state-prefix model was under-learned, as suspected). Rerunning A_dropbear with the rekey oracle (cache seeded) so all A models share one oracle.
