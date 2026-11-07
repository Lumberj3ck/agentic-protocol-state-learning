# TASKS (prioritized; state at 15:30, 2026-11-07)

Done:
1. [x] SUT containers OpenSSH 10.0p1, Dropbear 2025.88, Go x/crypto 0.58.0 (+ Dropbear 2020.81, 2022.83 for validation), pinned.
2. [x] Mapper: published Fiterau-Brostean mapper, patches P1-P5 (vendor/PATCHES.md); robust SUL, rekey-aware oracle.
3. [x] Literature notes (notes/literature.md).
4. [x] Diff tool, replay, taint filter, verification classifier (tests: 30).
5. [x] Validation: published finding + 4 published traces reproduce; Dropbear 2022.83 vs published model analysed.
6. [x] Models: A (5 inputs) for all three; B (7 inputs) for Dropbear and Go.
7. [x] Three-server replays of every distinguishing sequence; 39 divergence points in 9 classes.
8. [x] Five skeptical reviews (results/review/); all classes real.
9. [x] RFC adjudication per class (report.md table).
10. [x] Loop-cost metrics (results/loopcost_table.md, report.md).
11. [x] Freeze 15:22, final verification, report.md final.

Open (next session, in priority order):
1. [ ] B alphabet for OpenSSH (needs ~2-3 h; stopped unconverged at 15:01; cache in results/learning/B_openssh/cache_at_stop.json).
2. [ ] Strict-KEX mode in the mapper (send kex-strict-c-v00, reset sequence numbers at NEWKEYS) to learn the strict branch: D7/D8/D9 change there (reviews used stock paramiko).
3. [ ] Mapper P6: CH_MAX / dead-connection check; fix other CH_* inputs (Python 3 crash) to extend into the connection layer.
4. [ ] Decide with a human whether to report OpenSSH's RFC 4252 §6 / RFC 4253 §9 letter deviations upstream.

# v2 TASKS (from 16:00; streams run in parallel, see PROMPT.md v2 layout)

- [ ] A1 Run the teammate harness (strict KEX off and on) against our OpenSSH 10.0p1 / Dropbear 2025.88 / Go 0.58.0 containers; map alphabets; diff against our A/B models.
- [ ] A2 Adjudicate every harness-vs-harness disagreement (replay both harnesses + stock paramiko). Count and classify (bug in ours / bug in theirs / setup difference).
- [ ] A3 Run their catalogue on our models; write our D1-D9 as candidate catalogue JSON (catalogue-v2/ in our repo, not theirs).
- [ ] B1 Onboard Erlang/OTP, AsyncSSH, russh, libssh, wolfSSH, MINA, Paramiko server with our mapper; learn A (and B where feasible); replay D1-D9 representatives.
- [ ] B2 Version sweep: OpenSSH 6.9p1..10.x, Dropbear 2016..2025; replay D1-D9 representatives on each; find change points; learn A models at change points.
- [ ] C1 Strict KEX in mapper copy (v2); C2 CH_MAX/liveness + CH_* Python 3 fixes; C3 OpenSSH alphabet B to convergence; C4 re-learn affected models and diff v1 vs v2 abstraction.
- [ ] L Skeptic review per new finding; report v2 sections; journal merge; push.
