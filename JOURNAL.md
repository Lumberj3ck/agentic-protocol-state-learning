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
