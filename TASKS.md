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
