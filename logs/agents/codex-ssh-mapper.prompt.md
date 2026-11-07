Implement the SSH mapper specified in docs/MAPPER-SPEC-SSH.md, in src/smlearn/ssh/ (entry point src/smlearn/ssh/mapper.py exporting SSHMapper and INPUTS).

Rules:
- Read docs/MAPPER-SPEC-SSH.md fully first; it is the contract. Implement from the RFCs it names, using only the Python standard library and the `cryptography` package. Do NOT use any SSH library.
- Do NOT edit tests/conftest.py, tests/test_ssh_mapper.py, docs/, targets/ or src/smlearn/testbed.py. If you believe the spec or a test is wrong, stop and explain why in your final message instead of changing it.
- You may add offline unit tests in tests/test_ssh_wire.py (encoding, packet framing, key derivation).
- The validation tests run real servers in local Docker containers: `uv run pytest -q tests/test_ssh_mapper.py`. Iterate until all of them pass for all three targets (openssh, dropbear, asyncssh). Use `-x -k <name>` to focus.
- Keep the code small and readable: separate wire encoding, packet/crypto layer, and the mapper state machine.
- Finish with a short report: what passes, anything you could not make pass, and any choices the spec left open.
