# Patches to the vendored mapper (assist-project/ssh-fuzzer @ commit in ssh-fuzzer.COMMIT)

Each patch is marked `PSM patch Pn` in the source. Diff against upstream to audit.

- P1 `manualparamiko/transport.py`: opt-in `PSM_ALGOS=modern` prepends `diffie-hellman-group14-sha256` (KEX) and `rsa-sha2-256` (host key / pubkey sig).
  Default (`legacy`) is byte-identical upstream behaviour. Needed because current servers reject the upstream-only SHA-1 algorithms.
  The modified message handling lives in the DH-group KEX classes; `KexGroup14SHA256` subclasses them, so no crypto code was written.
- P2 `manualparamiko/transport.py`: username / passwords from `PSM_USER`, `PSM_PASS`, `PSM_BADPASS` (defaults = upstream hard-coded values).
- P3 `mapper/mapper.py`: when the learner disconnects, `recv` returns `b''`; upstream then crashed with `AttributeError: 'str' object has no attribute 'decode'`.
  Now the mapper waits for the next learner connection. Found 13:25 by the first replay smoke test.
