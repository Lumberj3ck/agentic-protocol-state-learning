Fixed per-direction pending-key consumption in `mapper.py`. Sequence resets now occur only when keys are installed. Added offline coverage for both direction orders and strict KEX modes: **14 tests pass**.

The OpenSSH regression still fails: server debug logs show it resets its receive sequence on the rejected extra NEWKEYS, then reports a MAC failure. Successful authentication therefore conflicts with the updated mapper rules on this target.

Per your instruction, I stopped and interrupted the full suite. No protected files were changed.