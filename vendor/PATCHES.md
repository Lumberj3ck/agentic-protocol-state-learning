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
- P5 `manualparamiko/transport.py` `_send_user_message`: send immediately instead of waiting on `clear_to_send`, which upstream never sets (its `.set()` is commented out).
  Found 13:25 by the skeptical reviewer (results/review/ua_without_sr.md): IGNORE and CH_OPEN (and other user messages) waited 30 s and killed the mapper.
  Correction (second reviewer, results/review/ch_open_preauth.md): TCP_FORWARD_* never used this path (it calls _send_message directly).
  Without this patch none of those inputs can be learned.

## Known unpatched mapper limitations (inputs NOT used in our alphabets)

- CH_CLOSE, CH_EOF, CH_DATA, CH_EXTENDED_DATA, CH_REQUEST_PTY, CH_REQUEST_ENV, CH_WINDOW_ADJUST crash the mapper on Python 3 (`get_remote_chanid_fuzz()` does `dict.keys()[0]`).
- CH_MAX: the mapper allows one channel, registers it even when the server rejects or the connection is dead, and then answers any further CH_OPEN with the mapper-made symbol CH_MAX without sending anything.
