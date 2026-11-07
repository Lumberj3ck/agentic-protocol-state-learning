# TASKS (prioritized; update as you go)

1. [ ] SUT containers: OpenSSH, Dropbear, Go x/crypto/ssh, pinned, password login verified with a real ssh client.
2. [x] Mapper (`psm/sshwire.py`, `psm/mapper.py`) with tests; full handshake + password auth works against every SUT.
3. [x] Literature notes (`notes/literature.md`): de Ruiter & Poll 2015; Fiterau-Brostean et al. 2017 (SSH).
4. [x] Model diff tool (`psm/diff.py`) with tests on synthetic Mealy machines.
5. [ ] Learn models per SUT (configs: strict-kex advertised vs not).
6. [ ] Diff models pairwise; replay every disagreement against both SUTs (`results/replay/`).
7. [ ] Skeptical review of each disagreement (mapper-bug hunt).
8. [ ] RFC adjudication per confirmed disagreement.
9. [ ] Loop-cost metrics table (mapper fixes, queries, human corrections).
10. [ ] 16:30 freeze -> final verification (tests + replay) -> report.md by 17:00.
