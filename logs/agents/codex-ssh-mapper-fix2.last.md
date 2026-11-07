Implemented both fixes and added offline regression tests:

- Offers both Curve25519 names, plus the strict-KEX marker when enabled.
- Preserves the first server KEXINIT’s strict-KEX decision throughout the connection.

All eight targets validated: **202 passed, 7 skipped**. Used `BUILDX_CONFIG=/tmp/ssh-mapper-buildx` to avoid Docker’s read-only home-directory error.

Only `src/smlearn/ssh/mapper.py` and `tests/test_ssh_wire.py` were edited.