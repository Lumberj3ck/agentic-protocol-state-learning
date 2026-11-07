# Patches to the vendored mapper (assist-project/ssh-fuzzer @ commit in ssh-fuzzer.COMMIT)

Each patch is marked `PSM patch Pn` in the source. Diff against upstream to audit.

- P1 `manualparamiko/transport.py`: opt-in `PSM_ALGOS=modern` prepends `diffie-hellman-group14-sha256` (KEX) and `rsa-sha2-256` (host key / pubkey sig).
  Default (`legacy`) is byte-identical upstream behaviour. Needed because current servers reject the upstream-only SHA-1 algorithms.
  The modified message handling lives in the DH-group KEX classes; `KexGroup14SHA256` subclasses them, so no crypto code was written.
- P2 `manualparamiko/transport.py`: username / passwords from `PSM_USER`, `PSM_PASS`, `PSM_BADPASS` (defaults = upstream hard-coded values).
- P3 `mapper/mapper.py`: when the learner disconnects, `recv` returns `b''`; upstream then crashed with `AttributeError: 'str' object has no attribute 'decode'`.
  Now the mapper waits for the next learner connection. Found 13:25 by the first replay smoke test.
- P4 `manualparamiko/transport.py` `_send_kex_init`: one KEXINIT cookie per connection (upstream drew a fresh random cookie per KEXINIT).
  Found 13:16 when learning OpenSSH 10.0: on `KEXINIT KEXINIT KEX30` OpenSSH answers the second KEXINIT with UNIMPL and keeps the first,
  but the mapper hashed the second payload as I_C, so it rejected OpenSSH's genuine host-key signature and crashed (`Signature verification (rsa-sha2-256) failed`).
  With identical payloads the exchange hash no longer depends on which KEXINIT the server keeps.
  Only sequences that previously crashed the mapper can change behaviour.
