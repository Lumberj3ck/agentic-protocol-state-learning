# Paramiko 5.1.0: blocked by native KEX support

Pinned to the latest stable PyPI release checked on 2026-11-07:
https://pypi.org/project/paramiko/5.1.0/

The threaded ServerInterface server uses native transport defaults, a generated
RSA host key, password-only test/test authentication, session channels and exec
completion with status 0. No algorithms are patched or aliased.

Validation:

```sh
SMLEARN_TARGETS=paramiko uv run pytest -q tests/test_ssh_mapper.py
```

The initial invocation hit a sandbox restriction writing Docker buildx activity
under ~/.docker. Re-running with BUILDX_CONFIG=/tmp/paramiko-buildx succeeded in
building and running the tests: **5 failed, 11 passed, 1 skipped**.
Full assertion output is in validation.txt; server output is in negotiation.txt.

| Test | Result |
| --- | --- |
| alphabet_is_complete | PASS |
| happy_path_completes | FAIL |
| strict_kex_is_negotiated | PASS |
| wrong_password_fails | FAIL |
| session_works_after_auth | FAIL |
| no_channel_sends_nothing | PASS |
| disconnect_then_no_conn | PASS |
| trace_records_packets | FAIL |
| queries_are_deterministic, seq0 through seq6 | PASS (each) |
| newkeys_without_new_kex_keeps_keys | SKIP (OpenSSH-only) |
| rekey_after_auth_installs_fresh_keys | FAIL |

The first client KEXINIT produces CLOSED. Server output:

```text
paramiko.ssh_exception.IncompatiblePeer: Incompatible ssh peer (no acceptable kex algorithm)
```

Upstream source reference: the PyPI 5.1.0 source distribution, paramiko/transport.py
lines 215–226 (_preferred_kex), line 335 (_kex_info), and lines 2429–2444
(_parse_kex_init). Its sole Curve25519 name is
`curve25519-sha256@libssh.org`; it does not implement the mapper's required
`curve25519-sha256` name. The parser raises IncompatiblePeer when there is no
intersection. Source archive:
https://files.pythonhosted.org/packages/76/cb/b1fde76618d84b1acf54d3d03d2b833ba5878afd12b9899346cc080f209d/paramiko-5.1.0.tar.gz

Strict KEX is supported and its negotiation test passes. Authentication, channel,
exec, and rekey behavior cannot be validated with this mapper because initial
key exchange fails. Determinism passes cover the resulting closed connections.
Stopped without a workaround, as required for implementation differences.
