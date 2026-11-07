# CANDIDATE-001: OpenSSH resets its receive sequence number on a stray NEWKEYS under strict KEX

Status: **confirmed conformance observation, informational / low severity**.
Reproduced on OpenSSH 9.2p1 (Debian bookworm) and on Alpine edge `openssh-server-10.6_p2-r0` (`sshd -V`: `OpenSSH_10.6p2`; there is no upstream `V_10_6_P2` tag, the source was verified at `V_10_6_P1` and master).
Independently verified in source by a Codex agent: [CANDIDATE-001-verification.md](CANDIDATE-001-verification.md).
Published on 2026-11-07 by team decision, before contacting the maintainers, because it cannot be triggered by an on-path attacker between honest endpoints.

## Observation

Target: OpenSSH 9.2p1 from Debian bookworm (`targets/openssh`, strict KEX backport), client offers `kex-strict-c-v00@openssh.com`.
After a completed handshake, the client sends SSH_MSG_NEWKEYS outside any key exchange
(pre-auth, after a refused rekey, or post-auth).
The server answers SSH_MSG_UNIMPLEMENTED, keeps the current keys,
and resets its receive sequence number to 0.

Evidence (`scripts/seqnr_experiment.py`, 3 runs each, deterministic):

| Variant | Next packet |
|---|---|
| A: strict KEX, client keeps its sequence number | MAC failure, connection closed |
| B: no strict KEX | accepted |
| C: strict KEX, client resets its own sequence number to 0 | accepted |

Dropbear 2024.85 and AsyncSSH 2.17.0 disconnect on the same stray NEWKEYS.
First noticed by the Codex mapper agent from server debug output while fixing a mapper bug,
then confirmed by Claude with the experiment above.

## Root cause

Upstream `openssh-portable` master, `packet.c`, in the receive path (`ssh_packet_read_poll2`, lines 1860–1863 when read on 2026-11-07):

```c
if (*typep == SSH2_MSG_NEWKEYS && ssh->kex->kex_strict) {
    debug_f("resetting read seqnr %u", state->p_read.seqnr);
    state->p_read.seqnr = 0;
}
```

The reset happens in the packet layer for every received NEWKEYS,
before the dispatcher decides the message is unexpected and answers UNIMPLEMENTED,
so the counter is reset although no new keys are installed.
The send path (lines 1380–1383) has the same shape, but OpenSSH only sends NEWKEYS inside a key exchange.

## Why it matters (assessment, low confidence)

draft-miller-sshm-strict-kex-01 §3.3 / OpenSSH PROTOCOL §1.9: the sequence number is reset after sending or receiving NEWKEYS.
The text does not say whether this applies to a NEWKEYS that is not part of a key exchange.
OpenSSH follows the literal text; the other two treat the message as a protocol error.
We read this as a **specification ambiguity**, not a vulnerability; the verification found no normative violation either way.
Creating a fresh valid encrypted NEWKEYS requires the current directional keys, so it takes the legitimate (but misbehaving) peer;
an on-path attacker between two honest endpoints cannot trigger it.
Once a misbehaving peer has sent it, the receiver's transport state breaks an invariant (verification §4):
with `chacha20-poly1305@openssh.com` (nonce and Poly1305 key derived from the sequence number) the receiver can accept
earlier packets of the same direction and key epoch again, and a peer that also resets its own counter reuses nonces in its sending direction;
AES-GCM is unaffected (independent IV counter); HMAC/UMAC see repeated sequence inputs.
These consequences are source-derived, not demonstrated at runtime (our mapper only speaks AES-128-CTR + HMAC-SHA2-256).
The OpenSSH client shares the packet-layer reset: after authentication it continues like the server, during authentication it terminates.

## Next checks

1. ~~Current upstream OpenSSH~~: same code at V_9_6_P1, V_9_9_P2, V_10_6_P1 and master (introduced in 1edb00c, 2023-12-18); behaviour reproduced on 10.6p2 (Alpine).
2. ~~Read upstream `packet.c`~~: done, see Root cause.
3. Other strict-KEX implementations (Go x/crypto/ssh, libssh, russh, wolfSSH, MINA): does any other reset without new keys?
4. Test with `chacha20-poly1305@openssh.com` once the mapper supports it.
5. Decide with the team whether this is worth a note to the OpenSSH developers and to the draft author.
