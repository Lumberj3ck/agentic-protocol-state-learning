Change the SSH mapper in src/smlearn/ssh/ (which you wrote) to allow at most one channel.

docs/MAPPER-SPEC-SSH.md was updated: re-read the channel bullet under "Mapper state and out-of-order inputs" and the new `CH_MAX` output.
Rule: after the mapper sends CHANNEL_OPEN, the channel is pending until CHANNEL_OPEN_CONFIRMATION (then open) or CHANNEL_OPEN_FAILURE (then none).
While a channel is pending or open, CH_OPEN sends nothing and returns "CH_MAX". Sending or receiving CHANNEL_CLOSE ends the channel as before.
Why: servers that accept unlimited channels (Dropbear, AsyncSSH) made the learned system infinite-state.

Failing test: `SMLEARN_TARGETS=dropbear uv run pytest -q tests/test_ssh_mapper.py -k one_channel`.
Then everything must pass on all targets:
`SMLEARN_TARGETS=openssh,dropbear,asyncssh,openssh-alpine-edge,paramiko,golang-xcrypto,libssh,erlang-otp,erlang-otp-27.3.2,russh,wolfssh,wolfssh-master,mina-sshd uv run pytest -q tests/`
Add an offline unit test for the pending/open/none transitions in tests/test_ssh_wire.py.

Rules: do NOT edit tests/conftest.py, tests/test_ssh_mapper.py, docs/, targets/ or src/smlearn/testbed.py or src/smlearn/learn.py.
If a failure is a real server behaviour difference rather than a mapper bug, stop and report it with evidence. Finish with a short report.
