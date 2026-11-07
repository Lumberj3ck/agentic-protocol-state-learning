# Validation result

Version: libssh 0.12.2, the latest stable release listed by
https://www.libssh.org/ on 2026-11-07. Official source archive and checksum
are pinned in Dockerfile and target.json.

Command (temporary Docker client directory required by this environment):

```sh
DOCKER_CONFIG=/tmp/libssh-docker-config SMLEARN_TARGETS=libssh uv run pytest -q tests/test_ssh_mapper.py
```

Result: **15 passed, 1 failed, 1 skipped in 76.07s**.
Full pytest output: [pytest-output.txt](pytest-output.txt).

| Test | Result |
| --- | --- |
| test_alphabet_is_complete | PASS |
| test_happy_path_completes[libssh] | PASS |
| test_strict_kex_is_negotiated[libssh] | PASS |
| test_wrong_password_fails[libssh] | PASS |
| test_session_works_after_auth[libssh] | PASS |
| test_no_channel_sends_nothing[libssh] | PASS |
| test_disconnect_then_no_conn[libssh] | PASS |
| test_trace_records_packets[libssh] | PASS |
| test_queries_are_deterministic[libssh-seq0] | PASS |
| test_queries_are_deterministic[libssh-seq1] | PASS |
| test_queries_are_deterministic[libssh-seq2] | PASS |
| test_queries_are_deterministic[libssh-seq3] | PASS |
| test_queries_are_deterministic[libssh-seq4] | PASS |
| test_queries_are_deterministic[libssh-seq5] | PASS |
| test_queries_are_deterministic[libssh-seq6] | PASS |
| test_newkeys_without_new_kex_keeps_keys[libssh] | SKIP: OpenSSH-only test |
| test_rekey_after_auth_installs_fresh_keys[libssh] | FAIL |

## Authenticated rekey difference

A separate reproduction using the unchanged mapper and testbed produced:

```text
initial strict_kex_active: True
KEXINIT => NO_RESP strict= True
KEX30 => KEX31+NEWKEYS strict= True
NEWKEYS => NO_RESP strict= True
SR_AUTH => SERVICE_ACCEPT strict= True
UA_PW_OK => UA_SUCCESS strict= True
KEXINIT => KEXINIT strict= False
KEX30 => KEX31+NEWKEYS strict= False
NEWKEYS => NO_RESP strict= False
CH_OPEN => NO_RESP strict= False
```

The initial server KEXINIT includes `kex-strict-s-v00@openssh.com`;
the authenticated rekey KEXINIT omits it. Both offer curve25519-sha256.
The mapper sets strict_kex_active to False on receipt of the second KEXINIT.
libssh retains strict KEX and resets packet sequence numbers on NEWKEYS.
This gives incompatible sequence numbers for the following encrypted traffic.
The test fails at the final CH_OPEN_SUCCESS assertion (actual: NO_RESP),
after both key exchanges have returned KEX31+NEWKEYS.

Relevant libssh source references, all in the exact official
[0.12.2 source archive](https://www.libssh.org/files/0.12/libssh-0.12.2.tar.xz):

- `src/server.c:226–231`, ssh_server_set_kex: explicitly skips appending
  extensions during authenticated rekey.
- `src/kex.c:916–945`, ssh_kex_append_extensions: appends the server strict
  KEX marker to the initial algorithm list.
- `src/kex.c:557–565`: enables the persistent SSH_SESSION_FLAG_KEX_STRICT
  when the client offers strict KEX.
- `src/packet.c:2100–2102`: resets send_seq on NEWKEYS in strict KEX.
- `src/packet_cb.c:164–166`: resets recv_seq on NEWKEYS in strict KEX.

The unchanged mapper's SSHMapper._received assigns strict_kex_active from
whether each received KEXINIT contains the server marker, and _install uses
that value to decide whether to reset sequence numbers. The mismatch is
therefore an interoperability finding, not a missing cipher or a target
configuration error. No workaround was applied; work stopped as requested.
All-pass validation could not be achieved under the rule prohibiting mapper
changes and workarounds for implementation behavior differences.
