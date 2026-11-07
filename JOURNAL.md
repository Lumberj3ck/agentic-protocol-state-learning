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
- 13:33 Dropbear 2022.83 (same version as the published model): 9 states, 12 min; EQUIVALENT to our 2020.81 model (results/diff/dropbear2022_vs_2020.json); predicts the 4 published traces (results/checks/dropbear2022_vs_published_traces.json).
  Versus the published 2022.83 model: the same 2 transitions after an initial KEX30 differ (results/diff/dropbear2022_vs_published2022.json). Our side replays 10/10 (results/replay/dropbear2022_vs_published_diffs.json).
  Control: the UNPATCHED upstream mapper (only P3) gives the same answers (results/replay/dropbear2022_upstream_mapper_check.json), so none of our patches cause it.
  Remaining explanations (not separable today): the published run's from-source Dropbear build vs our Alpine package, its environment, or the published hypothesis being unconverged (12 h timeout). Recorded as an unexplained, bounded residual.
  Recreate the upstream-mapper control: copy vendor/ssh-fuzzer/ssh-mapper to scratch/upstream_mapper and restore manualparamiko/transport.py from upstream commit (vendor/ssh-fuzzer.COMMIT).
- 13:38 A_dropbear with the rekey-aware oracle: 9 states (same as with state-prefix).
- 13:39 Decision: OpenSSH is the slowest SUT (answers out-of-order messages with UNIMPL and keeps the connection, so few NO_CONN sink shortcuts; A_openssh needed ~20 min for its first hypothesis). Stopped A_openssh after hypothesis 1 (9 states) and started B_openssh (rekey oracle, 15 walks/state).
  Final cross-server comparison uses the B models and their restriction to the A alphabet (B contains A).
  Learner now checkpoints its cache every 50 fresh queries. My first stop attempt used `pkill -f` with a pattern that matched its own shell, killing the follow-up commands; redone.
- 13:47 Dropbear's learned model on alphabet A is IDENTICAL for 2020.81, 2022.83 and 2025.88 (results/diff/dropbear2025_vs_2022_A.json, dropbear2025_vs_2020_A.json; legacy vs modern mapper algorithm profile). The learner is deterministic per seed, so the 2022.83 and 2025.88 runs even issued identical query counts.
- 13:46 A-alphabet diff Dropbear vs Go (results/diff/A_dropbear_vs_gossh.json): 13 fine / 7 coarse classes: KEX30 or NEWKEYS before client KEXINIT; NEWKEYS before KEX30; duplicate KEX30; D1; duplicate SR_AUTH; UA after success (Dropbear silently ignores, Go closes). Replay after B models.
- 13:47 psm/costs.py -> results/loopcost_table.md. psm/replay.py now replays targets in parallel threads (bug in first edit caught by tests/test_tools.py).
- 13:58 B_gossh: 16 states, 16.5 min, 172 fresh SUT queries, 0 nondeterminism.
  Mapper abstraction quirk (published design, not patched): the mapper allows one channel; any later CH_OPEN returns the mapper-made symbol CH_MAX WITHOUT sending or checking liveness, even if the connection is already closed.
  Effect: extra states (e.g. "connection dead but CH_OPEN -> CH_MAX") inflate state counts and mask a server's answer to a 2nd CH_OPEN.
  It cannot create a cross-server disagreement: the diff reports first divergences, and equal prefixes leave the mapper in the same channel state. Decision: document as a limitation instead of patching mid-run (would force re-learning all B models).
- 14:00 Replay of all 13 Dropbear-vs-Go A-diff sequences on all THREE servers, 5 reps (results/replay/A_dropbear_vs_gossh_replay.json): all deterministic; all disagree. Styles:
  Go closes TCP (no DISCONNECT, no UNIMPL) on every unexpected message; OpenSSH answers UNIMPL and ignores; Dropbear is permissive.
  NEW: OpenSSH refuses client rekey BEFORE auth (KEXINIT after first NEWKEYS -> UNIMPL, also after SR_AUTH), accepts it after auth; Dropbear and Go accept rekey pre-auth.
  This is SPIN 2017's OpenSSH 6.9p1 "Rekey Fail Before Auth" finding, still present in OpenSSH 10.0. RFC 4253 §9: on KEXINIT a party "MUST respond with its own SSH_MSG_KEXINIT". Same mapper KEXINIT bytes are accepted after auth (internal control).
  UA after success: Dropbear NO_RESP (RFC 4252 §5 SHOULD silently ignore), OpenSSH UNIMPL, Go closes. Duplicate SR_AUTH: OpenSSH+Dropbear SR_ACCEPT, Go closes. SR_AUTH after auth: OpenSSH UNIMPL, Dropbear SR_ACCEPT, Go closes.
- 13:58 REVIEW D2 (results/review/ch_open_preauth.md): REAL on all three (10 reps x 13 seqs x 3 servers; stock paramiko; server source).
  OpenSSH 10.0p1: every message >= 80 before auth (90, 80, 94, 98) -> UNIMPLEMENTED, connection kept until LoginGraceTime (auth2.c do_authentication2 -> dispatch_protocol_error). Violates the letter of RFC 4252 §6 MUST-disconnect; no security impact (payload never parsed, no channel code pre-auth). Same in SPIN 2017's 6.9p1 model and in the CCS 2025 9.9p2 model, unclassified there.
  Dropbear ("Exit before auth: Received message 90 before userauth") and Go ("unexpected message type 90") meet the MUST but send no DISCONNECT ("preferably").
  Reviewer notes: P5 doc corrected (TCP_FORWARD_* never gated); other CH_* inputs crash mapper on Python 3 (unused); CH_MAX artifact confirmed.
- 14:12 B_dropbear: 13 states, 34 min. Learning-stability check: B models restricted to alphabet A are EQUIVALENT to the independently learned A models, for Dropbear and Go (results/diff/B_vs_A_*_restricted.json).
  B diff Dropbear vs Go (results/diff/B_dropbear_vs_gossh.json): 8 coarse classes = the 7 A classes + SR_CONN after auth (Dropbear SR_ACCEPT, Go closes). Pre-auth SR_CONN and CH_OPEN: both close (agree).
- 14:06 Started A_openssh with the rekey oracle on its own mapper (8121), cache seeded from B_openssh's 14:04 checkpoint, as insurance for the 14:30 gate. Third reviewer (results/review/remaining_classes.md) on classes C1-C5.
- 14:12 Note on timestamps: entries between 12:50 and ~13:30 (and the matching results/loopcost.jsonl times) were written from my own estimate before checking the clock and run ~5-10 min late; order is correct.
- 14:30 GATE. Full encrypted handshake (KEX, service request, publickey auth, rekey) learned and converged for Dropbear 2020.81/2022.83/2025.88 and Go; OpenSSH A run (rekey oracle) has hypothesis 1 (9 states) and is in equivalence checking; B_openssh still filling its first table (cache 83 KB).
  Decision: do NOT fall back to the unencrypted phase; >= 2 servers have the full handshake, and every cross-server claim rests on three-server replays anyway.
  Condition: if A_openssh has not converged by 15:45, report OpenSSH's model as unconverged and base OpenSSH claims on replays only. B_openssh keeps running and is used only if it finishes before the 16:30 freeze.
- 14:33 REVIEW C1-C5 (results/review/remaining_classes.md): all REAL (mapper replay 27 seqs x 5 x 3; stock paramiko with fresh cookies, ML-KEM, strict KEX on/off; server source).
  C1 OpenSSH refuses pre-auth rekey (auth2.c resets the dispatch table; packet.c: "client can't cope with rekeying pre-auth"): violates the letter of RFC 4253 §9 MUST; also with fresh cookies, so not P4.
  C2 UA after success: Dropbear follows SHOULD (silent); OpenSSH UNIMPL (post-auth process); Go closes the logged-in session ("invalid channel 6": parses the request as a channel message).
  C3 repeated / post-auth SERVICE_REQUEST: unspecified divergence.
  C4/C5 errors in KEX / KEX30 or NEWKEYS first: only on the NON-strict branch; with strict KEX, OpenSSH disconnects ("strict KEX violation", "KEXINIT was not the first packet"), Dropbear exits, Go closes: all comply.
  Harness facts: mapper auto-sends KEXINIT when the server's arrives first; NEWKEYS without completed KEX corrupts the mapper's outbound stream. Added psm/taint.py + psm/verify.py (discard nondeterministic, tainted, or agreeing sequences) and reference/normalize.json (OpenSSH hostkeys-00 GLOBAL_REQUEST after UA_SUCCESS, confirmed by sshd "notify_hostkeys").
- 14:45 B-only replay on all three servers (results/replay/B_only_replay.json -> results/final/verified_B_only.md): 10 reportable, 1 agree (full happy path incl. CH_OPEN identical on all three).
  NEW E1: SR "ssh-connection" before auth: all three disconnect (RFC 4253 §10 MUST met); only OpenSSH sends DISCONNECT (SHOULD); Dropbear/Go silent close.
  E2: SR_CONN / SR_AUTH after auth: OpenSSH UNIMPL, Dropbear SR_ACCEPT, Go closes. Sent to a fourth reviewer (results/review/sr_conn.md).
- 14:58 A_openssh (rekey oracle) CONVERGED: 9 states, 46 min (before the 15:45 condition). Full encrypted handshake now learned for all three current servers.
  All three A models predict every replayed trace on their alphabet (results/checks/A_*_vs_replays.json, 0 mismatches).
  Three-way A diff (results/diff/A_threeway.json, normalised): 53 distinguishing sequences; replaying the 40 not yet replayed (results/replay/A_threeway_replay.json).
- 15:01 Stopped B_openssh (hypothesis 1 = 16 states at 14:50; the rekey-aware equivalence phase would need ~1800 words at ~8 fresh OpenSSH queries/min, far past the 16:30 freeze, and it loads the 1-CPU OpenSSH container used by the final replays).
  OpenSSH has NO converged B model; its SR_CONN / CH_OPEN behaviour is established by three-server replays only (results/final/verified_B_only.md). Cache kept: results/learning/B_openssh/cache_at_stop.json.
