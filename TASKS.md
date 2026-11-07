# Tasks

Prioritized. The loop takes the top open task, does it, and updates this list.
Each task names the check that says it is done.

## Open

0. **One-channel bound in the mapper** (`CH_MAX`, prompt ready in `logs/agents/codex-ssh-mapper-fix3.prompt.md`), then relearn all 12 targets (Dropbear and AsyncSSH did not converge without it).

3. **Learn first models** of openssh, dropbear, asyncssh with `python -m smlearn.learn`.
   Done when `results/<target>/model.dot` and `learn.json` exist and `nondet_events` is reported.
4. **Ground truth check**: compare the learned models with published SSH model-learning results
   (Fiterau-Brostean et al., SPIN 2017) for the behaviours they report.
5. **Differential + catalogue run** on the first three models; replay every disagreement on the real targets.
6. **Onboard more implementations**, one subagent each, in parallel:
   Paramiko, Go x/crypto/ssh, libssh, wolfSSH, russh, Apache MINA SSHD, Erlang/OTP ssh, TinySSH,
   plus older versions (pre-strict-KEX OpenSSH, Dropbear) as known-bug controls.
   Done per target when `tests/test_ssh_mapper.py` passes against it.
   *Needs more compute than the laptop: ask the user about the Nebius VM before scaling.*
7. Second protocol (MQTT 5 or CoAP) with the same pipeline.

6b. Catalogue gaps (see `literature/ssh-rfc-notes.md`): add a mapper input that reuses a closed channel id (CH_DATA after CH_CLOSE),
   UA_SUCCESS at most once (RFC 4252 §5.1), and fix the spec's strict-KEX reference
   (OpenSSH PROTOCOL §1.9 at V_9_6_P1 / draft-miller-sshm-strict-kex-01, not §1.10) after the mapper run, then refresh `logs/protected.sha256`.

## Done

- **SSH mapper** (Codex CLI, 2026-11-07): `tests/test_ssh_mapper.py` passes on openssh, dropbear, asyncssh (112 tests total).

- **SSH bug catalogue from the RFCs** (Claude subagent, 2026-11-07): 15 patterns in `catalogue/ssh/`,
  quotes verified against the RFC text in `literature/ssh-rfc-notes.md`,
  `tests/test_catalogue_ssh.py` + `tests/test_analysis.py`: 59 passed. Not yet run on learned models.
