# CANDIDATE-002: libssh leaves a stray-NEWKEYS session in an error state with an open socket

Status: confirmed local conformance observation; provisional informational / low severity.
Investigated on 2026-11-07 against existing Docker targets published only on 127.0.0.1.
Downloaded source was inspected only, never built or executed.

## Observation

After initial key exchange, a stray SSH_MSG_NEWKEYS makes libssh 0.12.2 stop processing that connection.
It neither replies nor immediately closes TCP.
Correct password authentication subsequently produces no reply, regardless of strict KEX or a client sequence reset.
This is a terminal session error left open by the target application's event loop, not installation of empty keys, a key exchange waiting for completion, or evidence of a whole-server hang.

The original `results/seqnr/*.txt` cover twelve implementations/configurations.
For bare NEWKEYS, libssh is silent in all variants; russh continues with the original transport state; OpenSSH continues with a strict-mode receive-counter reset; the remaining targets close.
The “pre-auth refused rekey” row must be interpreted separately: the preceding inputs can constitute a real rekey or fail earlier, so its final NEWKEYS is not uniformly a stray message across implementations.
The bare pre-auth and post-auth rows isolate this observation.

## Local experiments and exact outputs

Reproduction command: `uv run python scripts/stray_newkeys_followup.py`.
The new script uses the unchanged mapper and testbed, AES-128-CTR / HMAC-SHA2-256, and only the existing libssh Docker image.
Each NEWKEYS and immediate authentication/channel probe waits five seconds.
Variants A/B/C mean strict with retained counter, non-strict with retained counter, and strict with outgoing counter reset respectively.
Four affected sessions remain open together while a fifth connection completes authentication and opens a channel.
Raw output is preserved in [libssh-followup.txt](../results/seqnr/libssh-followup.txt).

```text
target 127.0.0.1 libssh 0.12.2
prefix [('KEXINIT', 'NO_RESP'), ('KEX30', 'KEX31+NEWKEYS'), ('NEWKEYS', 'NO_RESP'), ('SR_AUTH', 'SERVICE_ACCEPT')]
A NEWKEYS NO_RESP
A UA_PW_OK NO_RESP
prefix [('KEXINIT', 'NO_RESP'), ('KEX30', 'KEX31+NEWKEYS'), ('NEWKEYS', 'NO_RESP'), ('SR_AUTH', 'SERVICE_ACCEPT')]
B NEWKEYS NO_RESP
B UA_PW_OK NO_RESP
prefix [('KEXINIT', 'NO_RESP'), ('KEX30', 'KEX31+NEWKEYS'), ('NEWKEYS', 'NO_RESP'), ('SR_AUTH', 'SERVICE_ACCEPT')]
C NEWKEYS NO_RESP
C UA_PW_OK NO_RESP
prefix [('KEXINIT', 'NO_RESP'), ('KEX30', 'KEX31+NEWKEYS'), ('NEWKEYS', 'NO_RESP'), ('SR_AUTH', 'SERVICE_ACCEPT'), ('UA_PW_OK', 'UA_SUCCESS')]
post-auth NEWKEYS NO_RESP
post-auth CH_OPEN NO_RESP
prefix [('KEXINIT', 'NO_RESP'), ('KEX30', 'KEX31+NEWKEYS'), ('NEWKEYS', 'NO_RESP'), ('SR_AUTH', 'SERVICE_ACCEPT'), ('UA_PW_OK', 'UA_SUCCESS')]
parallel healthy CH_OPEN CH_OPEN_SUCCESS
process-before 1 (server) S 0 1 1 0 -1 4194560 1064 0 6 0 5 2 0 0 20 0 5 0 10334148 385650688 1367 18446744073709551615 94322935566336 94322935568333 140735810353680 0 0 0 0 4096 0 0 0 0 17 11 0 0 0 0 0 94322935578048 94322935578912 94323093209088 140735810359173 140735810359181 140735810359181 140735810359280 0
Threads:	5
idle 10 NO_RESP
idle 20 NO_RESP
idle 30 NO_RESP
idle 40 NO_RESP
idle 50 NO_RESP
idle 60 NO_RESP
idle 70 NO_RESP
idle 80 NO_RESP
idle 90 NO_RESP
idle 100 NO_RESP
idle 110 NO_RESP
idle 120 NO_RESP
idle elapsed 120.11
process-after 1 (server) S 0 1 1 0 -1 4194560 1064 0 6 0 7 3 0 0 20 0 5 0 10334148 385650688 1367 18446744073709551615 94322935566336 94322935568333 140735810353680 0 0 0 0 4096 0 0 0 0 17 11 0 0 0 0 0 94322935578048 94322935578912 94323093209088 140735810359173 140735810359181 140735810359181 140735810359280 0
Threads:	5
stats 0.01% 5.832MiB / 15.02GiB 5
logs-before-close 'Socket error: disconnected\nSocket error: disconnected\n'
logs-after-close 'Socket error: disconnected\nSocket error: disconnected\nSocket error: disconnected\nSocket error: disconnected\nSocket error: disconnected\nSocket error: disconnected\n'
```

`NO_RESP` means the collection deadline expired without an SSH response or TCP EOF; it is not a claim that the server thread was blocked inside a cipher routine.
The first affected connection remained open and silent for the full 120.11-second idle watch, in addition to the preceding setup and probes.
No server-initiated closure was observed; the clients were then closed by the script.
The idle watch is bounded and cannot establish that a connection never closes.
Across the watch, process user/system CPU ticks rose from 5/2 to 7/3 (three ticks total), with five threads before and after.
Docker reported 0.01% CPU at the final sample, supporting an idle polling state rather than a CPU spin.
The process counters below measure this existing thread-per-connection target, not every possible application embedding libssh.
Docker logs are captured before and after the clients close their sockets.
The existing application logs only `Socket error: disconnected`, including after client closure; they do not expose the earlier packet-filter error.
The exact filter path is established by tagged source inspection rather than a runtime trace of internal state.
No verbose variant was added.

The separate russh rerun uses `uv run python scripts/seqnr_experiment.py russh` (three repetitions per cell).
Exact output is also preserved in [russh-followup.txt](../results/seqnr/russh-followup.txt).

```text
russh     pre-auth refused rekey   | A: NEWKEYS->NO_RESP, UA_PW_OK->UA_SUCCESS | B: NEWKEYS->NO_RESP, UA_PW_OK->UA_SUCCESS | C: NEWKEYS->NO_RESP, UA_PW_OK->UA_SUCCESS
russh     pre-auth bare NEWKEYS    | A: NEWKEYS->NO_RESP, UA_PW_OK->UA_SUCCESS | B: NEWKEYS->NO_RESP, UA_PW_OK->UA_SUCCESS | C: NEWKEYS->NO_RESP, UA_PW_OK->CLOSED
russh     post-auth bare NEWKEYS   | A: NEWKEYS->NO_RESP, CH_OPEN->CH_OPEN_SUCCESS | B: NEWKEYS->NO_RESP, CH_OPEN->CH_OPEN_SUCCESS | C: NEWKEYS->NO_RESP, CH_OPEN->CLOSED
```

## Tagged source and root cause

Source archives are stored under the requested scratch directory `codex-libssh-russh-src`.
The GitHub tag `libssh-0.12.2` resolves through annotated tag object `2d3aa9b36ab543049ca002c5b85c310ac328469b` to commit `07430deb9b97b751ec5ea5a7fc307f40bf042e0a`.
The russh `v0.65.1` tag resolves to `b33092aad1e51c66258a12e8b83fc473a68d9d34`.
SHA-256 of the downloaded codeload archives:

```text
92fef8a348070a6786667ed724d5e808d2530464bac37559a8d59c70ab1f1a83  libssh.tar.gz
fedda194924e6ec1c24f3247dfe8aab2c88c26db3e54a961318e9987297de655  russh.tar.gz
```

All libssh file:line references below refer to that tag.
[packet.c:68](https://github.com/libssh/libssh-mirror/blob/libssh-0.12.2/src/packet.c#L68) registers `ssh_packet_newkeys` in the default callback table.
However, [packet.c:326–351](https://github.com/libssh/libssh-mirror/blob/libssh-0.12.2/src/packet.c#L326) first filters NEWKEYS:

```c
if (session->session_state != SSH_SESSION_STATE_DH) {
    rc = SSH_PACKET_DENIED;
    break;
}
```

It additionally requires `dh_handshake_state == DH_STATE_NEWKEYS_SENT`.
After initial KEX, the bare message fails the session-state requirement.
[packet.c:1575–1588](https://github.com/libssh/libssh-mirror/blob/libssh-0.12.2/src/packet.c#L1575) executes callbacks only for allowed packets.
The denied branch records `Packet filter: rejected packet (type %d)` with `SSH_FATAL` and jumps to `error`.
[packet.c:1626–1629](https://github.com/libssh/libssh-mirror/blob/libssh-0.12.2/src/packet.c#L1626) then does:

```c
session->session_state = SSH_SESSION_STATE_ERROR;
SSH_LOG(SSH_LOG_PACKET, "Packet: processed %zu bytes", processed);
return processed;
```

This branch does not send DISCONNECT, close the socket, or clear `alive`.
On subsequent input, [packet.c:1309–1311](https://github.com/libssh/libssh-mirror/blob/libssh-0.12.2/src/packet.c#L1309) tests the error state and jumps straight to the same error return, before packet decryption.
The socket callback at [socket.c:377–385](https://github.com/libssh/libssh-mirror/blob/libssh-0.12.2/src/socket.c#L377) consumes only the returned byte count and stops retrying when that count is zero.
This explains silence without an immediate busy loop; further incoming bytes may remain buffered instead of being processed.
No memory-growth stress experiment was performed.

Even if reached directly, [packet_cb.c:155–162](https://github.com/libssh/libssh-mirror/blob/libssh-0.12.2/src/packet_cb.c#L155) repeats the same session/DH checks and errors before the strict receive-counter reset at lines 164–166.
Its error path at lines 280–288 also sets the session error state.
Thus this observation is not the OpenSSH reset-before-dispatch behavior from CANDIDATE-001.

Neither filter failure nor callback state-check failure touches `next_crypto` or `current_crypto`.
The real key-switch routine, [packet.c:2165–2220](https://github.com/libssh/libssh-mirror/blob/libssh-0.12.2/src/packet.c#L2165), marks directional use of `next_crypto`, retires current directional use, and promotes `next_crypto` only once both directions have switched.
It then allocates a fresh pending crypto object and copies the session ID into it.
That pending object existing after KEX does not mean it becomes active on a stray NEWKEYS: this error path never calls `ssh_packet_set_newkeys()`.
The existing current crypto remains installed, but the session error gate prevents using it for later packets.
The authenticated but rejected stray packet itself increments the receive counter in the normal packet path at packet.c:1538; no strict reset occurs.

## Per-connection versus whole-server impact

`targets/libssh/server.c` creates a detached thread per accepted connection.
After `ssh_handle_key_exchange()`, its thread loops on `ssh_is_connected(s)` and calls `ssh_event_dopoll(event, 1000)`, breaking only on `SSH_ERROR`.
[session.c:712–718](https://github.com/libssh/libssh-mirror/blob/libssh-0.12.2/src/session.c#L712) implements connection status as `return session->alive;`, without checking `session_state`.
[Poll handling at poll.c:743–748](https://github.com/libssh/libssh-mirror/blob/libssh-0.12.2/src/poll.c#L743) returns `SSH_AGAIN` on an idle timeout.
Consequently the application can keep polling an errored but still alive socket.
The application prints `ssh_get_error()` only after leaving that loop.
In this run the later socket-disconnection error was what appeared in those logs; the original filter error was not preserved there.
Applications which explicitly detect terminal session errors and disconnect may have a different lifetime.

The successful parallel connection proves the listener and other connection threads remain functional with four affected connections present.
The CPU and closure observations are bounded measurements reported above, not a claim of unlimited resource exhaustion.

## Short comparison: russh 0.65.1

In [server/mod.rs:1206](https://github.com/Eugeny/russh/blob/v0.65.1/russh/src/server/mod.rs#L1206), `reply()` classifies key-exchange messages with `is_kex_msg`.
[msg.rs:165–170](https://github.com/Eugeny/russh/blob/v0.65.1/russh/src/msg.rs#L165) includes NEWKEYS in that set.
[server/mod.rs:1240–1242](https://github.com/Eugeny/russh/blob/v0.65.1/russh/src/server/mod.rs#L1240) only passes such packets to the KEX machine if the session is `SessionKexState::InProgress`.
After KEX completes it sets the state to Idle at line 1295.
An idle stray NEWKEYS therefore falls through to `session.server_read_encrypted(handler, pkt).await` at line 1312.

[server/encrypted.rs:35–41](https://github.com/Eugeny/russh/blob/v0.65.1/russh/src/server/encrypted.rs#L35) forwards to `process_packet()`.
During authentication, its state/message match has no NEWKEYS arm and ends at line 161 with `_ => Ok(())`.
After authentication, lines 150–159 route to `server_read_authenticated()`; its final arm at lines 2020–2023 is:

```rust
m => {
    debug!("unknown message received: {m:?}");
    Ok(())
}
```

This is the no-op which accounts for silence and continued use of existing crypto.
Key installation and strict sequence reset occur only in the real KEX completion branch, server/mod.rs:1255–1300.
“Unchanged sequence numbers” here means no reset: normal packet-number advancement still occurs when the stray packet is read.
Variant A continuing while C closes is consistent with that distinction.
There is no demonstrated key replacement, sequence rollback, authentication bypass, or session availability loss in russh's bare-message path.

## Severity and confidence

Assessment: **informational / low**, with high confidence in the libssh state transition and russh no-op, and moderate confidence in deployment impact.
A peer can trigger libssh's state error before user authentication, after completing transport KEX.
A fresh valid encrypted stray NEWKEYS requires that peer's transport keys; this does not establish a trigger available to an on-path attacker between honest endpoints.
The local result is loss of progress on the sending peer's own session and retained connection/thread resources until cleanup.
An idle client already retains resources in this target; the experiment does not establish an amplification factor or a distinct whole-server denial of service.
There is no observed CPU spin, crash, authentication bypass, plaintext disclosure, or switch to uninitialised cryptography.
The library's terminal error and the embedding application's cleanup policy must be considered together before assigning broader availability impact.

## Summary

libssh rejects out-of-KEX NEWKEYS, enters a terminal session error before key switching, and this target keeps polling the open connection.
Other connections still work.
russh silently ignores the message outside active KEX and continues with existing keys and normally advancing counters.
