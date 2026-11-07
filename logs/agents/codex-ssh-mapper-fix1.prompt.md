Fix a bug in the SSH mapper (src/smlearn/ssh/) that you wrote earlier.

The spec docs/MAPPER-SPEC-SSH.md, section "Mapper state and out-of-order inputs", now states that pending keys are kept per direction and consumed when installed, and that a NEWKEYS with no pending keys leaves that direction's keys, cipher state and sequence number unchanged (including under strict KEX). Read that section again.

Bug: `self.pending` is never cleared, so a second NEWKEYS without a new completed key exchange re-installs the old keys (restarting the AES-CTR keystream) and, under strict KEX, resets the sequence number. The server then sees a MAC failure, which is a mapper artifact.

Failing test: `uv run pytest -q tests/test_ssh_mapper.py -k newkeys_without` (OpenSSH). Make it pass, and keep everything else passing: `uv run pytest -q tests/` (Docker targets start automatically). Add an offline unit test for the per-direction consumption in tests/test_ssh_wire.py if you can.

Rules: do NOT edit tests/conftest.py, tests/test_ssh_mapper.py, docs/, targets/ or src/smlearn/testbed.py. If you think the spec or a test is wrong, stop and explain why. Finish with a short report of what changed and the test results.
