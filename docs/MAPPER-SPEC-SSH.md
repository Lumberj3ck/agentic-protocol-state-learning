# SSH mapper specification

The mapper turns abstract input symbols into concrete SSH transport messages,
sends them to a real server,
and turns everything the server sends back into one abstract output symbol.
The learning algorithm only ever sees abstract symbols,
so the mapper must be **deterministic**:
the same input sequence after `reset()` must always give the same outputs.

It lives in `src/smlearn/ssh/` and is implemented from the RFCs only
(RFC 4251–4254, RFC 8731, RFC 5656, RFC 4344, RFC 6668,
and OpenSSH `PROTOCOL` section 1.9 at V_9_6_P1 and draft-miller-sshm-strict-kex-01 for strict KEX).
**No third-party SSH library** (no paramiko, asyncssh, etc.):
use `cryptography` for X25519, AES-CTR and HMAC.

## Interface

```python
from smlearn.ssh.mapper import SSHMapper, INPUTS

m = SSHMapper(host, port, user="test", password="test", strict_kex=True)
m.reset()                  # new TCP connection, version exchange, absorb server KEXINIT
out = m.step("KEXINIT")    # -> "KEXINIT" etc.
m.trace                    # list of (direction, msg_name, payload_hex) for the current query
m.close()
```

Constructor keyword arguments, with defaults:
`timeout=1.0` (max seconds to wait for the first reply packet in a step),
`quiet=0.15` (after a packet arrives, keep reading until nothing arrives for this long),
`strict_kex=True` (advertise `kex-strict-c-v00@openssh.com`).

`reset()` closes any previous connection,
opens a new one,
sends `SSH-2.0-smlearn_0.1\r\n`,
reads the server identification line (skipping any lines before it that do not start with `SSH-`),
and absorbs whatever the server sends during the quiet window,
which is normally its KEXINIT.
The server KEXINIT payload is stored for the exchange hash.
Nothing received during `reset()` is reported as output.

## Algorithms

Offer exactly one algorithm per category, so negotiation is deterministic:

- kex: `curve25519-sha256,curve25519-sha256@libssh.org` (the same algorithm under its two names; the second is the only one Paramiko offers), plus `kex-strict-c-v00@openssh.com` when `strict_kex=True`
- host key: `ssh-ed25519,rsa-sha2-256,ecdsa-sha2-nistp256` (the signature is not verified; this is a local testbed)
- cipher: `aes128-ctr`
- MAC: `hmac-sha2-256`
- compression: `none`

## Input alphabet

`INPUTS` is this tuple, in this order:

| Symbol | Concrete message |
|---|---|
| `KEXINIT` | SSH_MSG_KEXINIT (20) with a fixed cookie of 16 zero bytes |
| `KEX30` | SSH_MSG_KEX_ECDH_INIT (30) with a fresh X25519 public key |
| `NEWKEYS` | SSH_MSG_NEWKEYS (21) |
| `SR_AUTH` | SSH_MSG_SERVICE_REQUEST (5) for `ssh-userauth` |
| `SR_CONN` | SSH_MSG_SERVICE_REQUEST (5) for `ssh-connection` |
| `UA_PW_OK` | SSH_MSG_USERAUTH_REQUEST (50), method `password`, correct credentials |
| `UA_PW_NOK` | same with a wrong password |
| `UA_NONE` | SSH_MSG_USERAUTH_REQUEST (50), method `none` |
| `CH_OPEN` | SSH_MSG_CHANNEL_OPEN (90), type `session`, window 2^21, max packet 32768 |
| `CH_CLOSE` | SSH_MSG_CHANNEL_CLOSE (97) |
| `CH_EOF` | SSH_MSG_CHANNEL_EOF (96) |
| `CH_DATA` | SSH_MSG_CHANNEL_DATA (94) with data `b"x"` |
| `CH_REQUEST_EXEC` | SSH_MSG_CHANNEL_REQUEST (98) `exec`, want_reply true, command `true` |
| `IGNORE` | SSH_MSG_IGNORE (2) with empty data |
| `DEBUG` | SSH_MSG_DEBUG (4), always_display false, empty message and language |
| `UNIMPLEMENTED` | SSH_MSG_UNIMPLEMENTED (3) with sequence number 0 |
| `DISCONNECT` | SSH_MSG_DISCONNECT (1), reason 11 (BY_APPLICATION) |

### Mapper state and out-of-order inputs

Inputs can arrive in any order.
The mapper must send them anyway whenever it can build the bytes,
because how the server reacts to unexpected messages is exactly what we want to learn.

- The mapper keeps the latest client KEXINIT payload it sent,
  the latest server KEXINIT payload it received,
  and its latest X25519 private key.
- When a KEX_ECDH_REPLY (31) arrives,
  and the mapper has both KEXINIT payloads and a private key,
  it computes the shared secret, the exchange hash H and the session id
  (H of the first exchange, never replaced on rekey),
  and derives *pending* keys (RFC 4253 section 7.2).
  If it is missing something, it derives nothing.
- Pending keys are kept **per direction** and are consumed when installed:
  each key exchange that completes (a KEX_ECDH_REPLY processed as above) gives one pending key set for outgoing
  and one for incoming.
- Sending `NEWKEYS` switches the **outgoing** direction to its pending keys, if there are any, and clears them;
  otherwise the outgoing direction keeps its current keys, cipher state and sequence number unchanged.
- Receiving NEWKEYS from the server switches the **incoming** direction to its pending keys, if there are any, and clears them;
  otherwise the incoming direction is unchanged.
  (Re-installing already used keys would restart the AES-CTR keystream, and the peer would see a MAC failure that is
  an artifact of the mapper, not behaviour of the server.)
- Strict KEX applies when the mapper offered it and the server's **first** KEXINIT of the connection contained `kex-strict-s-v00@openssh.com`.
  It then stays in force for the whole connection: the marker is only meaningful in the initial KEXINIT and is ignored in later ones
  (OpenSSH PROTOCOL §1.9; Go x/crypto/ssh and libssh omit it when rekeying but keep resetting sequence numbers).
  Then the outgoing sequence number resets to 0 when sending NEWKEYS installs new keys,
  and the incoming one resets to 0 when receiving NEWKEYS installs new keys.
- Sequence numbers count every packet in each direction from the start of the connection (uint32, wrapping).
- The channel inputs `CH_CLOSE`, `CH_EOF`, `CH_DATA` and `CH_REQUEST_EXEC` use the server's channel id
  from the latest CHANNEL_OPEN_CONFIRMATION.
  If no channel is open, the mapper sends nothing and the output is `NO_CHANNEL`.
  `CH_OPEN` is always sent.
  After the mapper sends or receives CHANNEL_CLOSE, the channel is no longer open.
- The mapper never answers server messages on its own:
  no automatic replies to KEXINIT, GLOBAL_REQUEST, CHANNEL_REQUEST or window adjustments.

## Output abstraction

`step()` sends the message, then reads packets:
it waits up to `timeout` for the first one,
and after each packet keeps reading until nothing arrives for `quiet` seconds.
The output is the names of the received messages joined with `+`, in arrival order.

Message names: `DISCONNECT, IGNORE, UNIMPLEMENTED, DEBUG, SERVICE_ACCEPT, EXT_INFO, KEXINIT, NEWKEYS, KEX31, UA_FAILURE, UA_SUCCESS, UA_BANNER, GLOBAL_REQUEST, REQUEST_SUCCESS, REQUEST_FAILURE, CH_OPEN_SUCCESS, CH_OPEN_FAILURE, CH_WINDOW_ADJUST, CH_DATA, CH_EXTENDED_DATA, CH_EOF, CH_CLOSE, CH_REQUEST, CH_SUCCESS, CH_FAILURE`.
Any other message number becomes `MSG<n>`.
Consecutive repeats of the same name collapse into one (for example `CH_DATA+CH_DATA` becomes `CH_DATA`),
because their number depends on timing.

Special outputs:

- `NO_RESP`: nothing arrived within `timeout`.
- `+CLOSED`: appended when the connection closes (EOF or reset) during the step, e.g. `DISCONNECT+CLOSED`, or just `CLOSED` when nothing came before it.
- `NO_CONN`: the connection was already closed before this step. Nothing is sent.
- `NO_CHANNEL`: see above.
- `BAD_PACKET`: an incoming packet could not be decrypted or failed its MAC check.
  The mapper then treats the connection as closed.

`trace` is reset by `reset()` and records every packet sent and received in the current query,
as `(">" or "<", name, payload.hex())`,
so any disagreement can be replayed and inspected.

## Validation

The tests in `tests/test_ssh_mapper.py` run against real servers in Docker
(OpenSSH, Dropbear, AsyncSSH)
and must all pass:
the happy-path handshake completes,
wrong credentials fail,
repeated queries give identical outputs,
and closed connections behave as specified.

After `reset()`, `strict_kex_active` is `True` when strict KEX applies to this connection (see above), else `False`.
