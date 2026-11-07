Onboard one SSH *server* implementation as a test target for our state-learning pipeline.
Implementation: wolfSSH (C, with wolfSSL). Target name: wolfssh. Hints: build wolfSSL and wolfSSH from tagged release tarballs (configure wolfSSL with --enable-ssh, and wolfSSH with --enable-all or what is needed for password auth and exec); use or adapt wolfSSH's examples/echoserver. NOTE: a concurrent fix to the mapper is in progress for two known issues (strict KEX must persist after a rekey KEXINIT without the marker; kex name curve25519-sha256@libssh.org). Failures caused only by those two issues are expected: record them and continue.

Read first: docs/MAPPER-SPEC-SSH.md, src/smlearn/testbed.py, tests/conftest.py, tests/test_ssh_mapper.py, and targets/asyncssh/ as an example.

Create targets/wolfssh/ with:
- Dockerfile building the **latest stable release** of wolfSSH (C, with wolfSSL), pinned to an exact version (no "latest" tags for the implementation itself). Prefer official packages/images; build from a tagged source release if needed. Keep the image small.
- Any server program needed (many libraries are not servers by themselves: write a minimal server using the library's own API). The server must listen on port 22 inside the container, accept password authentication for user `test` with password `test` (and nothing else), accept `session` channels, and answer an `exec` request (any command; returning exit status 0 is enough). Generate the host key at build or start time.
- The server must offer, among others: kex curve25519-sha256 (and the strict KEX extension if the implementation supports it), host key ssh-ed25519 or rsa-sha2-256 or ecdsa-sha2-nistp256, cipher aes128-ctr, MAC hmac-sha2-256, compression none.
- target.json: {"name": "wolfssh", "implementation": "...", "source": "<exact version and where it comes from>", "port": 22, "user": "test", "password": "test"}

Validate: `SMLEARN_TARGETS=wolfssh uv run pytest -q tests/test_ssh_mapper.py`. Iterate on the target (not on the mapper) until it passes.

Rules:
- Do NOT edit anything outside targets/wolfssh/. In particular never edit src/, tests/, docs/.
- If a test fails because of a real behaviour difference of wolfSSH (C, with wolfSSL) (not a configuration mistake in your target), or because the mapper lacks an algorithm the implementation requires, stop and report it precisely, with the output and the relevant source/doc reference of wolfSSH (C, with wolfSSL). Such differences are research results, not things to work around.
- Containers are started by the testbed bound to 127.0.0.1 only; do not publish ports otherwise and do not contact other hosts except package registries.
- Finish with a short report: version onboarded, test results (pass/fail per test), any behaviour differences observed, anything you could not do.
