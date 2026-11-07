# CANDIDATE-001 verification

Verified on 2026-11-07 by source inspection and experiments against Docker targets bound to 127.0.0.1.
Verdict: **confirmed** for the server after initial KEX, with important client-state and impact qualifications.
No downloaded source was built or executed.
The only existing repository file read for execution was the authorized experiment; this report is a new file.

## 1. Receive path and key state — confirmed

In [V_10_6_P1 packet.c:1736–1786](https://github.com/openssh/openssh-portable/blob/V_10_6_P1/packet.c#L1736), the packet is authenticated/decrypted using the current receive sequence number, that original number is saved for dispatch, and the counter is incremented.
At packet.c:1849–1852, the test is simply `if (*typep == SSH2_MSG_NEWKEYS && ssh->kex->kex_strict)`, followed by `state->p_read.seqnr = 0;`.
It does not test whether a KEX is active or new keys are pending.
This occurs inside `ssh_packet_read_poll2()` before it returns through the read API to the dispatcher.
In [V_10_6_P1 dispatch.c:87–114](https://github.com/openssh/openssh-portable/blob/V_10_6_P1/dispatch.c#L87), reading precedes `(*ssh->dispatch[type])(type, seqnr, ssh)`.
Thus the reset precedes the decision that NEWKEYS is unexpected.
The UNIMPLEMENTED payload contains the original received sequence number, not the reset value.

In [V_10_6_P1 kex.c:429–437](https://github.com/openssh/openssh-portable/blob/V_10_6_P1/kex.c#L429), `kex_send_newkeys()` resets the transport dispatch table, sends NEWKEYS, then registers `kex_input_newkeys` as the expected receive handler.
At kex.c:562–575, the legitimate receive handler immediately restores NEWKEYS to `kex_protocol_error`, checks the payload end, and calls `ssh_set_newkeys(ssh, MODE_IN)`.
At kex.c:600–603 it marks KEX complete and clears `KEX_INITIAL` and KEX-init flags.
At kex.c:994–1015, strict KEX is selected only during initial KEX by checking the opposite role's strict marker, and remains enabled afterwards.
At kex.c:232–246, `kex_protocol_error()` disconnects for an unexpected message during strict initial KEX, but otherwise constructs `SSH2_MSG_UNIMPLEMENTED` and returns success.

The exact handler outside KEX depends on the application phase, rather than always being `dispatch_protocol_error()`.
[V_10_6_P1 auth2.c:175–179](https://github.com/openssh/openssh-portable/blob/V_10_6_P1/auth2.c#L175) initializes the server authentication dispatcher with `dispatch_protocol_error`.
[V_10_6_P1 serverloop.c:905–922](https://github.com/openssh/openssh-portable/blob/V_10_6_P1/serverloop.c#L905) does the same for the server connection loop and explicitly enables KEXINIT for rekeying.
Both that default handler, at dispatch.c:40–51, and `kex_protocol_error()` send UNIMPLEMENTED.
Neither installs keys.

[V_10_6_P1 packet.c:976–1040](https://github.com/openssh/openssh-portable/blob/V_10_6_P1/packet.c#L976) shows that installing keys requires moving `ssh->kex->newkeys[mode]` into packet state and rebuilding the cipher context via `cipher_init()`.
The stray-message receive branch never calls this routine.
The receive key, cipher context, CTR/CBC state or GCM invocation state, and MAC key stay in use; only the SSH receive sequence counter is reset by this branch.
The opposite direction's send counter is not reset by receiving NEWKEYS, including when sending the UNIMPLEMENTED response.
The send-side reset at packet.c:1376–1382 is adjacent to an unconditional `ssh_set_newkeys(ssh, MODE_OUT)` for an outgoing NEWKEYS, so it must not be described as an equivalent supported way for OpenSSH to send stray NEWKEYS while retaining keys.

## 2. OpenSSH client symmetry — partly

The packet-layer behavior is shared between client and server and the receive reset has no role check.
After authentication, [V_10_6_P1 clientloop.c:2844–2862](https://github.com/openssh/openssh-portable/blob/V_10_6_P1/clientloop.c#L2844) sets the default handler to `dispatch_protocol_error`, enables KEXINIT, and leaves stray NEWKEYS on the default error path.
An established client therefore also resets, sends UNIMPLEMENTED, retains current keys, and continues.
After a subsequent completed KEX, the restored `kex_protocol_error` handler has the same nonfatal outcome.

During user authentication, however, [V_10_6_P1 sshconnect2.c:462–465 and 563–566](https://github.com/openssh/openssh-portable/blob/V_10_6_P1/sshconnect2.c#L462) installs `input_userauth_error` as the default handler, which calls `fatal_f("bad message during authentication: type %d", type)`.
In that phase a stray server NEWKEYS still resets the counter first, but terminates the client instead of sending UNIMPLEMENTED and continuing.
Unexpected initial strict-KEX NEWKEYS also terminates through KEX error handling.
Client conclusions are source-verified, not reproduced with a malicious local server.

## 3. Introduction and versions — confirmed

The introducing portable commit is [1edb00c58f8a6875fad6a497aa2bacf37f9e6cd5](https://github.com/openssh/openssh-portable/commit/1edb00c58f8a6875fad6a497aa2bacf37f9e6cd5), dated 2023-12-18, titled `upstream: implement "strict key exchange" in ssh and sshd`.
Its OpenBSD commit ID is `2a66ac962f0a630d7945fee54004ed9e9c439f14`.
The downloaded patch adds the unconditional strict NEWKEYS receive reset; the introducing packet.c already has it at lines 1693–1696.
The GitHub tags API and packet.c commit-history API supplied tag SHAs, dates, and commit messages.
Individual API lookups for the introduction and rekey-hardening commits returned HTTP 403, so their exact diffs were obtained with curl from GitHub commit patch URLs and checked against raw source.

| Revision | Resolved tag/commit SHA | Receive reset | Expected NEWKEYS handler / restoration |
| --- | --- | --- | --- |
| V_9_6_P1 | 8241b9c0529228b4b86d88b1a6076fb9f97e4a99 | packet.c:1693–1696 | kex.c:650 / 780–784 |
| V_9_9_P2 | d76b2675116617394cd355a3437b4963a562b64d | packet.c:1784–1787 | kex.c:402 / 533–537 |
| V_10_6_P1 | a8c72b842423f0774f542d3c2197247c3dd28d74 | packet.c:1849–1852 | kex.c:434 / 571–575 |
| master | 5dba72adacbd39736960543373737bc01e35f778 | packet.c:1860–1863 | kex.c:434 / 571–575 |

All four retain the relevant behavior.
The latest `V_10_*` tag returned by the tags API was **V_10_6_P1**, not V_10_6_P2.
Each version's raw packet.c, dispatch.c, kex.c, PROTOCOL, cipher.c, cipher-chachapoly.c and mac.c was downloaded under the requested scratch directory.
Master references describe the downloaded snapshot resolved above.

Later handling did change, but does not fix or prevent this stray-message reset.
[72b05ecd141b9683285dcdb439de01903c1a07d3](https://github.com/openssh/openssh-portable/commit/72b05ecd141b9683285dcdb439de01903c1a07d3), dated 2026-05-31, rejects non-KEX messages after receiving a KEXINIT and tracks `KEX_INIT_RECVD`.
In master packet.c:1968–1976 the new default-case check returns `SSH_ERR_PROTOCOL_ERROR` for such messages.
NEWKEYS passes `ssh_packet_type_is_kex()` at master packet.c:1396–1404, and a bare NEWKEYS outside KEX does not have the active-KEX prerequisite anyway.
This hardening therefore does not imply that unexpected NEWKEYS disconnects.
[f7a2c31dbfc10c2d1111830f6756ff9b3a1318dd](https://github.com/openssh/openssh-portable/commit/f7a2c31dbfc10c2d1111830f6756ff9b3a1318dd), dated 2026-10-30, changes strict-KEX failures from process-fatal handling to returned errors with poisoned packet state; master kex.c:237 still limits this strict unexpected-message failure to `KEX_INITIAL`.

## 4. Protocol impact — partly; misbehaving peer required

A party creating a fresh valid encrypted NEWKEYS after initial KEX needs the relevant directional encryption and authentication keys, barring cryptographic compromise or forgery.
This can be the legitimate remote endpoint and does not require successful SSH user authentication.
A passive observer or ordinary on-path attacker cannot choose or modify an authenticated packet's type to trigger this reset.
An attacker can retransmit ciphertext, so “only key holders can send one” needs the qualification that creation of a fresh valid packet differs from replay.
With two honest endpoints, old NEWKEYS packets do not provide this trigger: initial NEWKEYS was under the initial unencrypted transport, and rekey NEWKEYS was protected with the preceding keys, which the receiver replaces upon legitimate processing.
The finding supplies no way for an on-path attacker to get a valid stray NEWKEYS under the receiver's current keys and sequence state between honest endpoints.

For `chacha20-poly1305@openssh.com`, [V_10_6_P1 cipher-chachapoly.c:77–110 and 125–134](https://github.com/openssh/openssh-portable/blob/V_10_6_P1/cipher-chachapoly.c#L77) derives the nonce and per-packet Poly1305 key from `POKE_U64(seqbuf, seqnr)`.
After a misbehaving peer supplies the stray message, the honest receiver reuses old receive-side key/nonce combinations when processing sequence numbers starting again at zero.
Previously recorded packets from that same direction and current key epoch can then authenticate and decrypt again at matching sequence numbers, subject to application-state validation and intervening rekeying or closure.
A peer which also resets its sending counter and encrypts new packets under the retained key causes actual encryption nonce and Poly1305-key reuse in its own sending direction.
The honest receiver's reset does not make its independent outgoing direction reuse nonces.
These are source-derived consequences, not a demonstrated attack between honest peers or a runtime ChaCha replay test.

For AES-GCM, [V_10_6_P1 cipher.c:343–375](https://github.com/openssh/openssh-portable/blob/V_10_6_P1/cipher.c#L343) uses an independent cipher-context invocation IV (`EVP_CTRL_GCM_IV_GEN`), not the SSH sequence number as its nonce.
Keeping that context while resetting the SSH counter does not reset the GCM IV, does not cause GCM nonce reuse, and does not by itself allow old ciphertext to authenticate again.
The GCM path does not use a separate SSH MAC with the reset sequence number.

For HMAC and UMAC modes, [V_10_6_P1 mac.c:158–188](https://github.com/openssh/openssh-portable/blob/V_10_6_P1/mac.c#L158) uses the sequence number as an HMAC input prefix or UMAC nonce.
Packet.c:1736–1761 supplies it both for EtM authentication over ciphertext and conventional MAC authentication over plaintext.
Resetting therefore repeats MAC sequence inputs, and repeats UMAC nonces, but does not rewind CTR counters or CBC chaining state.
HMAC input-prefix reuse alone is not an HMAC break.
With conventional MACs and CTR/CBC, replayed ciphertext ordinarily decrypts differently and fails authentication; with CTR plus EtM, an old ciphertext tag can match the reset counter but cipher-stream desynchronization prevents reliable replay of the original plaintext packet.
CBC plus EtM also authenticates the old ciphertext at a reused sequence number, while its first plaintext block changes with the current chaining value, so packet parsing and application acceptance require separate analysis and must not be claimed generically.
No CBC/EtM or UMAC forgery or application replay was demonstrated here.
There is no honest-client/honest-server scenario established by this finding that reuses an encryption key/nonce pair or accepts a replay.
All identified new effects require a misbehaving or compromised endpoint first producing a valid stray NEWKEYS.

## 5. Specification and other implementations — confirmed with interpretation caveat

[Draft-miller-sshm-strict-kex-01 §3.3](https://datatracker.ietf.org/doc/html/draft-miller-sshm-strict-kex-01#section-3.3) places resets at KEX completion, but its operational receive instruction says the counter “MUST be reset after a SSH_MSG_NEWKEYS is received.”
That literal receive instruction matches OpenSSH's reset even for an unexpected packet, while the section's KEX-completion framing leaves treatment of stray NEWKEYS unclear.
[V_9_6_P1 PROTOCOL:161–164](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/PROTOCOL#L161) explicitly requires reset after sending or receiving NEWKEYS and says the behavior persists for the connection.
OpenSSH follows that literal rule.
Neither text explicitly requires continuing after an out-of-KEX NEWKEYS, so literal reset compliance does not prove that continuing is the intended specification behavior.
Calling this a specification ambiguity is reasonable editorial interpretation, not proof of a normative violation or proof that no security consequence can exist.

[Dropbear DROPBEAR_2024.85 src/common-kex.c:124–128](https://github.com/mkj/dropbear/blob/DROPBEAR_2024.85/src/common-kex.c#L124) checks `!(ses.kexstate.sentkexinit && ses.kexstate.recvkexinit)` in `switch_keys()` and calls `dropbear_exit("Unexpected newkeys message")`.
Its `recv_msg_newkeys()` at lines 194–205 calls `switch_keys()` before the strict-mode `ses.recvseq = 0`, so a bare stray NEWKEYS outside KEX exits before that reset.
At lines 151–160, completed exchanges call `kexinitialise()`; lines 241–243 clear the exchange state.
This confirms termination rather than continued operation with an unchanged key and reset counter.

[AsyncSSH v2.17.0 asyncssh/connection.py:2328–2344](https://github.com/ronf/asyncssh/blob/v2.17.0/asyncssh/connection.py#L2328) accepts NEWKEYS only if `_next_recv_encryption` exists, consumes that pending encryption state, and otherwise raises `ProtocolError('New keys not negotiated')`.
Packet processing calls that handler at lines 1596–1599, before the receive-sequence reset at lines 1623–1626.
The receive error path at lines 1335–1337 sends a disconnect and force-closes the connection.
Thus a stray message fails before the receive reset and the connection does not continue.
These other-implementation verdicts are from tagged source; the present verification did not rerun their containers.

## 6. Local experiments — confirmed

`uv run python scripts/seqnr_experiment.py openssh openssh-alpine-edge` completed successfully.
For each target and each prefix (pre-auth refused rekey, pre-auth bare NEWKEYS, post-auth bare NEWKEYS), all three repetitions were deterministic.
Every stray NEWKEYS returned UNIMPLEMENTED.
Variant A (strict, sender counter retained) then returned CLOSED; variant B (non-strict) and variant C (strict, sender counter reset) accepted the authentication or channel-open probe.
The abstraction reports CLOSED here, not an explicit MAC-error message; source analysis establishes the sequence-dependent authentication explanation.
The mapper uses AES-128-CTR with HMAC-SHA2-256, so these results establish counter reset and continuing cipher state, not ChaCha or GCM behavior experimentally.

A second inline experiment used `smlearn.testbed` and `SSHMapper`, with both targets, before and after authentication.
It sent a stray NEWKEYS, reset only the mapper's outgoing sequence to zero, sent IGNORE, then repeated that pair and sent the final authentication/channel-open probe.
All four runs produced `UNIMPLEMENTED, NO_RESP, UNIMPLEMENTED, NO_RESP` followed by `UA_SUCCESS+GLOBAL_REQUEST` before authentication or `CH_OPEN_SUCCESS` after authentication.
This confirms that a second stray NEWKEYS resets again while cipher state continues.
Observed banners were `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10` and `SSH-2.0-OpenSSH_10.6`.
The edge target's metadata says 10.6p2, but its banner does not establish that portable patchlevel, and upstream's latest tag is V_10_6_P1.
No remote SSH target was contacted.

## Corrections and final assessment

The original server observation and reset-before-dispatch root cause are correct.
Its conditional statement that a client which also resets can reuse ChaCha nonces is correct, but should explicitly identify that client as a misbehaving sender; the honest receiver does not thereby encrypt with repeated nonces.
A blanket “no replay” claim would also be wrong once a malicious peer has supplied the trigger; the original does not demonstrate that conditional ChaCha behavior.
Client symmetry needs the user-authentication termination exception.
The original's “current upstream 10.6p2” statement is not supported by the tag API or observed banner and should not be published as a verified upstream version.
The status text simultaneously says candidate/maintainers not contacted and “Published”; this verification establishes technical behavior only, not publication or disclosure status.

Severity: **informational / low**, with **high confidence** in the server state transition and source-level client qualification, and **moderate confidence** in the overall severity assessment.
The finding demonstrates permissive handling and a cryptographic state invariant violation induced by a misbehaving peer, including conditional ChaCha replay acceptance at the transport layer.
It does not demonstrate authentication bypass, disclosure of an honest peer's outgoing plaintext, privilege escalation, or an on-path attack between honest endpoints.
Publish as a qualified conformance/specification observation rather than an established remotely exploitable vulnerability.
