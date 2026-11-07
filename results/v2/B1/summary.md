# B1 summary (state at finalisation, 2026-11-07 ~16:30)

All seven servers were onboarded: each builds from a pinned image, negotiates with our mapper (modern profile: group14-sha256, rsa-sha2-256, aes128-ctr, hmac-sha2-256) and passes the 11-sequence smoke replay (3 reps) in `results/v2/B1/<impl>_final_seqs.json`.
Stock paramiko verified password and publickey login on each (see `suts/<impl>/VERSION.md`, `suts/b1/verify.py`); KEXINITs in `results/v2/B1/kexinit_<impl>.txt`.
Teammate Dockerfiles (Apache-2.0) were reused and extended; credit is in each VERSION.md.

| impl | version | how obtained | onboarded | model A |
|---|---|---|---|---|
| paramiko | 5.1.0 | PyPI in python:3.12-slim@sha256:4840d5... | yes, port 2301 / mapper 8301 | DONE: `results/models/b1_paramiko_A.dot`, 8 states, 998 learning queries |
| asyncssh | 2.17.0 | PyPI, same base | yes, 2302 / 8302 | learning running (results/learning/b1_asyncssh_A) |
| erlang-otp | OTP 29.1.2, ssh 6.0.7 | erlang:29.1.2.0-slim@sha256:2110a9... | yes, 2303 / 8303 | learning running |
| libssh | 0.12.2 | tarball sha256 49560f67..., bookworm-slim@sha256:734a72... | yes, 2304 / 8304 | learning running |
| russh | 0.65.1 | crates.io, rust:1.92.0-slim-bookworm@sha256:f1f735... ; `rsa` feature needed, Cargo.lock re-resolved (kept in image /Cargo.lock.resolved) | yes, 2305 / 8305 | learning started late (~16:25), running |
| mina-sshd | 2.20.1 | Maven Central, temurin 21 digests in VERSION.md | yes, 2306 / 8306 | learning running |
| wolfssh | 1.6.0 + wolfSSL 5.9.4 | release tarballs, sha256 in VERSION.md | yes, 2307 / 8307 | learning running |

Learning runs are left running on the box (`results/learning/b1_<impl>_A*`); models appear in `results/models/b1_<impl>_A.dot` when done.
Alphabet B, model diffs against A_openssh/A_dropbear/A_gossh and the NEW-divergence-point replay were NOT done (time).
Learners ran while one candidate replay briefly used their mapper ports (16:18); no nondeterminism or harness error files existed at 16:25, but treat any later nondet.jsonl entries with that in mind.

## Class matrix
`results/v2/B1/class_matrix.md` (cells = output at the divergence point of the D1-D9 representative; 3 reps for new servers, 5 for OpenSSH/Dropbear/Go from v1).
Observations to hand to a skeptic (NOT verified findings; mapper limits from vendor/PATCHES.md apply, no strict KEX):
- D6 (`KEXINIT KEX30 NEWKEYS SR_AUTH SR_CONN`): libssh answers SR_ACCEPT, russh stays silent, others disconnect.
- D3 (`... SR_AUTH KEXINIT`): Erlang/OTP disconnects, libssh and russh stay silent, the rest rekey (same split as OpenSSH vs Dropbear/Go).
- D4 (second USERAUTH after success): wolfssh and Erlang/OTP disconnect (RFC 4252 5.1 SHOULD silently ignore); paramiko, asyncssh, libssh, russh, Dropbear stay silent.
- D1 (USERAUTH without SERVICE_REQUEST): paramiko, asyncssh, libssh, wolfssh accept like Dropbear; mina answers UNIMPL like OpenSSH; Erlang disconnects; russh ignores.
- D2: paramiko answers CHANNEL_OPEN_FAILURE pre-auth and keeps the connection; libssh and russh stay silent.
The planned 5-rep replay with server logs of these points (`reference/v2_b1_candidate_seqs.json`, output `results/v2/B1/candidate_replay.json`) was still running at finalisation; no MUST/SHOULD deviation is claimed yet.
