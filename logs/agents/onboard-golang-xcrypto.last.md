Created `targets/golang-xcrypto/` with **x/crypto v0.58.0**, pinned in `go.mod`, and a roughly 6 MB runtime image.

Validation: **15 passed, 1 skipped, 1 failed**. Per-test results and output are in [README.md](targets/golang-xcrypto/README.md).

The failure is post-authentication rekey: `CH_OPEN -> CLOSED`. Go advertises strict KEX only during the initial exchange but retains its sequence-number resets. The mapper disables those resets when the rekey advertisement omits the marker. Relevant [Go handshake source](https://go.googlesource.com/crypto/+/refs/tags/v0.58.0/ssh/handshake.go) and [transport source](https://go.googlesource.com/crypto/+/refs/tags/v0.58.0/ssh/transport.go) are documented in the report.

Stopped without a workaround, as requested. All changes are confined to `targets/golang-xcrypto/`.