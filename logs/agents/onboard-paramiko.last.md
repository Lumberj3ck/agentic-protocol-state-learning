Created `targets/paramiko/` pinned to [Paramiko 5.1.0](https://pypi.org/project/paramiko/5.1.0/), with Dockerfile, threaded server, and metadata.

Validation: **11 passed, 5 failed, 1 skipped**. Per-test results and output are in [README.md](/home/lumberj3ck/code/probe/network-protocols/targets/paramiko/README.md).

Stopped on a native algorithm mismatch: Paramiko offers `curve25519-sha256@libssh.org`, while the mapper requires `curve25519-sha256`. Server output confirms:

```text
Incompatible ssh peer (no acceptable kex algorithm)
```

Strict KEX negotiation passes. Authentication, exec, and rekey remain unvalidated because initial key exchange fails. Source references are recorded in the report; no workaround or changes outside `targets/paramiko/` were made.