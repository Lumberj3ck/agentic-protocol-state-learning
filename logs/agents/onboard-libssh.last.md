Added `targets/libssh/` using **libssh 0.12.2**, pinned to the official release tarball with SHA-256 verification.

Validation: **15 passed, 1 failed, 1 skipped**. Authenticated rekey fails: libssh omits the strict-KEX marker on rekey but retains sequence resets; the mapper disables strict mode, and the subsequent channel open returns `NO_RESP`.

Stopped without a workaround or mapper changes, as requested. All created files are under `targets/libssh/`.

[Per-test results and libssh source references](targets/libssh/VALIDATION.md) · [Full pytest output](targets/libssh/pytest-output.txt)