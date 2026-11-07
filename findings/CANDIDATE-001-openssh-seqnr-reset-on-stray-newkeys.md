# CANDIDATE-001: OpenSSH resets its receive sequence number on a stray NEWKEYS under strict KEX

Status: **candidate**, confirmed by replay on OpenSSH 9.2p1 (Debian) and 10.6p2 (Alpine edge, current), root cause located in upstream source; maintainers not contacted.
Published on 2026-11-07 by team decision: we assess it as a spec ambiguity that an on-path attacker cannot trigger (see below).

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
This looks like a **spec ambiguity** rather than a vulnerability:
only a party holding the session keys can send an encrypted NEWKEYS, so an on-path attacker cannot trigger it.
With `chacha20-poly1305@openssh.com` (nonce = sequence number), a reset without rekeying would reuse nonces
for the sending client's own later packets, if the client also reset; we have not tested other ciphers.

## Next checks

1. ~~Current upstream OpenSSH~~: same behaviour in 10.6p2.
2. ~~Read upstream `packet.c`~~: done, see Root cause.
3. Other strict-KEX implementations (Go x/crypto/ssh, libssh, russh, wolfSSH, MINA): does any other reset without new keys?
4. Test with `chacha20-poly1305@openssh.com` once the mapper supports it.
5. Decide with the team whether this is worth a note to the OpenSSH developers and to the draft author.
