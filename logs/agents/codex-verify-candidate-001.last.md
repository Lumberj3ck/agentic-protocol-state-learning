Created [CANDIDATE-001-verification.md](/home/lumberj3ck/code/probe/network-protocols/findings/CANDIDATE-001-verification.md).

Confirmed: the server resets before dispatch, retains keys, and sends UNIMPLEMENTED. Both local targets reproduced the behavior, including repeated resets.

Key qualifications:

- The client terminates during authentication; established sessions continue.
- ChaCha replay consequences require a misbehaving peer; no on-path attack between honest endpoints was established.
- AES-GCM’s IV counter is unaffected.
- The original’s upstream `10.6p2` label is unsupported; latest tag found was `V_10_6_P1`.

Assessment: **informational / low severity**. No existing files modified.