Two fixes to the SSH mapper in src/smlearn/ssh/ (which you wrote), found while onboarding new targets.
docs/MAPPER-SPEC-SSH.md has been updated; re-read the "Algorithms" section and the strict-KEX bullet under "Mapper state and out-of-order inputs".

1. kex: offer `curve25519-sha256,curve25519-sha256@libssh.org` (same algorithm, two names), plus the strict-KEX marker. Paramiko 5.1.0 only offers the @libssh.org name (see targets/paramiko/README.md).
2. Strict KEX is decided by the server's FIRST KEXINIT only and then persists for the connection; later server KEXINITs (rekey) without the marker must not turn it off. Go x/crypto/ssh and libssh omit the marker on rekey but keep resetting sequence numbers (see targets/golang-xcrypto/README.md and targets/libssh/VALIDATION.md).

Validate on all targets: `SMLEARN_TARGETS=openssh,dropbear,asyncssh,openssh-alpine-edge,paramiko,golang-xcrypto,libssh,erlang-otp uv run pytest -q tests/` — everything must pass. Add offline unit tests for both points in tests/test_ssh_wire.py.

Rules: do NOT edit tests/conftest.py, tests/test_ssh_mapper.py, docs/, targets/ or src/smlearn/testbed.py. If a remaining failure is a real behaviour difference of a server (not a mapper bug), stop and report it precisely with the evidence instead of working around it. Finish with a short report.
