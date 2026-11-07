# SSH state machine rules: normative text

Normative sentences behind the conformance patterns in `catalogue/ssh/`.
Quotes are verbatim from the plain-text RFCs at rfc-editor.org,
from `draft-miller-sshm-strict-kex-01`,
and from the OpenSSH `PROTOCOL` file,
with line wrapping removed.
`[...]` marks an omission.
Each heading names the catalogue entries that encode the rule.

A note on the strict KEX source.
In current OpenSSH `master`, `PROTOCOL` section 1.9 ("transport: strict key exchange extension") only points to the Internet-Draft,
and section 1.10 is about `SSH2_MSG_EXT_INFO` during user authentication.
The full strict KEX text is in `PROTOCOL` section 1.9 of release `V_9_6_P1` and in the draft,
so both are quoted below.

Sources:

- RFC 4251, The Secure Shell (SSH) Protocol Architecture, https://www.rfc-editor.org/rfc/rfc4251.txt
- RFC 4252, The Secure Shell (SSH) Authentication Protocol, https://www.rfc-editor.org/rfc/rfc4252.txt
- RFC 4253, The Secure Shell (SSH) Transport Layer Protocol, https://www.rfc-editor.org/rfc/rfc4253.txt
- RFC 4254, The Secure Shell (SSH) Connection Protocol, https://www.rfc-editor.org/rfc/rfc4254.txt
- draft-miller-sshm-strict-kex-01, SSH Strict KEX extension, https://www.ietf.org/archive/id/draft-miller-sshm-strict-kex-01.txt
- OpenSSH `PROTOCOL` at V_9_6_P1, https://raw.githubusercontent.com/openssh/openssh-portable/V_9_6_P1/PROTOCOL

## Strict KEX

### Activation

Draft §3.1, MUST:

> Similarly, if the client offers support for the pre-standard extension name "kex-strict-c-v00@openssh.com" and the server advertises "kex-strict-s-v00@openssh.com" then both ends MUST enable the protocol changes below.

The mapper always offers `kex-strict-c-v00@openssh.com`,
and the targets (OpenSSH, Dropbear, AsyncSSH) advertise `kex-strict-s-v00@openssh.com`,
so every learned connection runs with strict KEX.
The server only learns that strict KEX applies when the client KEXINIT arrives.

### First packet must be KEXINIT (`STRICT-KEX-FIRST-KEXINIT`)

Draft §3.2, MUST:

> Because the message that signals support for strict KEX is enabled by the SSH_MSG_KEXINIT message, implementations MUST verify that the SSH_MSG_KEXINIT was the first message received from the peer.

> These check is noted separately, because they must happen somewhat retrospectively, unlike the other enforcement mentioned in this section.

OpenSSH `PROTOCOL` §1.9 (V_9_6_P1), item a), under "it MUST make the following changes to the the protocol":

> This includes terminating the connection if the first packet received is not SSH2_MSG_KEXINIT.

Because the check is retrospective,
a server may stay silent on the stray first packet
and terminate when the client KEXINIT arrives.

### No non-KEX messages during the initial KEX (`STRICT-KEX-NON-KEX-MSG`)

Draft §3.2, MUST:

> When strict KEX is enabled, implementations MUST terminate the connection if they receive a non-KEX message during the initial key exchange.

> Permitted messages include only SSH_MSG_KEXINIT, SSH_MSG_NEWKEYS and the messages specific to each KEX algorithm: [...]

> SSH_MSG_KEX_ECDH_INIT and SSH_MSG_KEX_ECDH_REPLY for ECDH KEX algorithms defined in (Section 7.1 of [RFC5656]) [...]

OpenSSH `PROTOCOL` §1.9 (V_9_6_P1), item a):

> During initial KEX, terminate the connection if any unexpected or out-of-sequence packet is received.

> Unexpected packets for the purpose of strict KEX include messages that are otherwise valid at any time during the connection such as SSH2_MSG_DEBUG and SSH2_MSG_IGNORE.

This overrides RFC 4253 §11 (IGNORE and DEBUG "at any time") for the initial KEX only.
For the server, the initial KEX lasts until it receives the client NEWKEYS.

### Each KEX message accepted the expected number of times (`STRICT-KEX-REPEATED-MSG`)

Draft §3.2, MUST:

> Finally, implementations MUST additionally ensure that any message permitted during KEX only be accepted the expected number of times.

> For example, for ECDH KEX, the SSH_MSG_KEX_ECDH_INIT will only be sent a single time by a well-behaved client.

> A server implementing this extension MUST only accept it once.

Together with "out-of-sequence" in `PROTOCOL` item a) (quoted above),
this covers a second KEXINIT, a second KEX_ECDH_INIT, and a NEWKEYS before KEX_ECDH_INIT.

### Sequence number reset (not encoded)

Draft §3.3, MUST:

> When strict KEX is enabled, both the client and server MUST reset their sequence numbers at the conclusion of the initial KEX and for each subsequent KEX.

The mapper does this reset itself,
so a server that does not reset shows up as `BAD_PACKET` or a MAC-error disconnect right after NEWKEYS.
That is caught by the mapper validation tests rather than by a pattern,
because `BAD_PACKET` can also come from a mapper bug.

## Transport layer (RFC 4253)

### Messages a party may send inside a key exchange (`KEX-SERVER-SENDS-NON-KEX`, `KEXINIT-DUPLICATE`, `SR-ACCEPT-BEFORE-NEWKEYS`)

RFC 4253 §7.1, MUST NOT:

> Once a party has sent a SSH_MSG_KEXINIT message for key exchange or re-exchange, until it has sent a SSH_MSG_NEWKEYS message (Section 7.3), it MUST NOT send any messages other than:
>
> o Transport layer generic messages (1 to 19) (but SSH_MSG_SERVICE_REQUEST and SSH_MSG_SERVICE_ACCEPT MUST NOT be sent);
>
> o Algorithm negotiation messages (20 to 29) (but further SSH_MSG_KEXINIT messages MUST NOT be sent);
>
> o Specific key exchange method messages (30 to 49).

> Note, however, that during a key re-exchange, after sending a SSH_MSG_KEXINIT message, each party MUST be prepared to process an arbitrary number of messages that may be in-flight before receiving a SSH_MSG_KEXINIT message from the other party.

This constrains the sender.
The server has sent its KEXINIT before the mapper's first step,
so until it sends NEWKEYS it must not send SERVICE_ACCEPT, KEXINIT, or any message numbered 50 or higher.

RFC 4253 §7.3:

> Key exchange ends by each side sending an SSH_MSG_NEWKEYS message.

> All messages sent after this message MUST use the new keys and algorithms.

### Service request after the key exchange (`SR-ACCEPT-BEFORE-NEWKEYS`)

RFC 4253 §10, descriptive (no keyword):

> After the key exchange, the client requests a service.

RFC 4253 §10, MUST:

> If the server rejects the service request, it SHOULD send an appropriate SSH_MSG_DISCONNECT message and MUST disconnect.

> If the server supports the service (and permits the client to use it), it MUST respond with the following:

RFC 4251 §1, descriptive:

> The client sends a service request once a secure transport layer connection has been established.

> A second service request is sent after user authentication is complete.

Before the server NEWKEYS, a SERVICE_ACCEPT breaks the §7.1 MUST NOT.
Between the server NEWKEYS and the client NEWKEYS the RFCs only describe the order,
so accepting there is a MUST violation only because strict KEX is active.
The §10 rule "reject means disconnect" is not encoded on its own:
servers commonly answer a repeated SERVICE_REQUEST with UNIMPLEMENTED,
and it is unclear whether such a message counts as a service request or as an unexpected message (§11.4).

### Key re-exchange (`REKEY-KEXINIT-REPLY`, `KEXINIT-DUPLICATE`)

RFC 4253 §9, MUST:

> Key re-exchange is started by sending an SSH_MSG_KEXINIT packet when not already doing a key exchange (as described in Section 7.1).

> When this message is received, a party MUST respond with its own SSH_MSG_KEXINIT message, except when the received SSH_MSG_KEXINIT already was a reply.

> Re-exchange is processed identically to the initial key exchange, except for the session identifier that will remain unchanged.

In the initial exchange the client KEXINIT is itself a reply to the server KEXINIT,
so answering it with another KEXINIT breaks both §9 and §7.1.

### Disconnect (`SEND-AFTER-DISCONNECT`, `RECV-AFTER-DISCONNECT`)

RFC 4253 §11.1, MUST:

> This message causes immediate termination of the connection.

> All implementations MUST be able to process this message; they SHOULD be able to send this message.

> The sender MUST NOT send or receive any data after this message, and the recipient MUST NOT accept any data after receiving this message.

### Ignore and debug (`IGNORE-DEBUG-TOLERATED`)

RFC 4253 §11.2, MUST:

> All implementations MUST understand (and ignore) this message at any time (after receiving the identification string).

RFC 4253 §11.3, MUST:

> All implementations MUST understand this message, but they are allowed to ignore it.

With strict KEX these hold only after the initial key exchange.

### Unrecognized messages (not encoded)

RFC 4253 §11.4, MUST:

> An implementation MUST respond to all unrecognized messages with an SSH_MSG_UNIMPLEMENTED message in the order in which the messages were received.

> Such messages MUST be otherwise ignored.

All 17 inputs are message numbers that every server recognizes,
so the alphabet cannot send a truly unrecognized message.
Whether a known message in the wrong state counts as "unrecognized" is not specified.

### Message numbers

RFC 4253 §12:

> Note that numbers 30-49 are used for kex packets.

## Authentication (RFC 4252)

### The ssh-userauth service must be requested first (`UA-BEFORE-SR-AUTH`)

RFC 4252 §1, descriptive:

> The 'service name' for this protocol is "ssh-userauth".

Together with RFC 4253 §10 and RFC 4251 §1 (quoted above),
the authentication protocol starts when the client requests `ssh-userauth`.
No sentence says that a server MUST reject USERAUTH_REQUEST before that,
so the pattern has level SHOULD.

### The "none" method and rejection (`AUTH-WITHOUT-CREDENTIALS`)

RFC 4252 §4, MUST:

> The "none" method is reserved, and MUST NOT be listed as supported.

> The server MUST always reject this request, unless the client is to be granted access without any authentication, in which case, the server MUST accept this request.

RFC 4252 §5.1, MUST:

> If the server rejects the authentication request, it MUST respond with the following:

> When the server accepts authentication, it MUST respond with the following:

RFC 4252 §8, descriptive:

> Normally, the server responds to this message with success or failure.

All three targets require the password `test` for user `test`,
so UA_NONE and UA_PW_NOK must never yield UA_SUCCESS,
also not after an earlier failure.
The wrong-password part follows from the meaning of password authentication,
not from an explicit MUST NOT.

### Success only once, then ignored (not encoded)

RFC 4252 §5.1, MUST and SHOULD:

> SSH_MSG_USERAUTH_SUCCESS MUST be sent only once.

> When SSH_MSG_USERAUTH_SUCCESS has been sent, any further authentication requests received after that SHOULD be silently ignored.

RFC 4252 §5.3, SHOULD:

> Authentication is complete when the server has responded with SSH_MSG_USERAUTH_SUCCESS.

> All authentication related messages received after sending this message SHOULD be silently ignored.

These are expressible but were left out to keep the catalogue at 15 entries.
"Success once" is two outputs containing UA_SUCCESS;
"silently ignored" is a UA_* input after UA_SUCCESS whose output contains UA_FAILURE, UA_SUCCESS, UNIMPLEMENTED, DISCONNECT or CLOSED.

### Connection-protocol messages before authentication (`CONN-BEFORE-AUTH`, `UNAUTH-CHANNEL-OPEN`)

RFC 4252 §6, MUST:

> Message numbers of 80 and higher are reserved for protocols running after this authentication protocol, so receiving one of them before authentication is complete is an error, to which the server MUST respond by disconnecting, preferably with a proper disconnect message sent to ease troubleshooting.

> After successful authentication, such messages are passed to the higher-level service.

RFC 4254 §1, descriptive:

> The SSH Connection Protocol has been designed to run on top of the SSH transport layer and user authentication protocols ([SSH-TRANS] and [SSH-USERAUTH]).

CHANNEL_OPEN is message 90,
so before UA_SUCCESS it must cause a disconnect.
A SERVICE_ACCEPT for `ssh-connection` before authentication is flagged on the strength of the layering (RFC 4251 §1, RFC 4254 §1),
since no sentence forbids it outright.

## Connection protocol (RFC 4254)

### Channel close must be answered (`CH-CLOSE-REPLY`)

RFC 4254 §5.3, MUST:

> When either party wishes to terminate the channel, it sends SSH_MSG_CHANNEL_CLOSE.

> Upon receiving this message, a party MUST send back an SSH_MSG_CHANNEL_CLOSE unless it has already sent this message for the channel.

> The channel is considered closed for a party when it has both sent and received SSH_MSG_CHANNEL_CLOSE, and the party may then reuse the channel number.

### Channel EOF (not encoded)

RFC 4254 §5.3:

> No explicit response is sent to this message.

> Note that the channel remains open after this message, and more data may still be sent in the other direction.

Not encoded:
the server may close its side after EOF reaches the command,
so CH_EOF followed by CH_CLOSE from the server is legal.

### Data after close (not expressible)

RFC 4254 §5.3 (above) defines when a channel is closed,
but says nothing explicit about CHANNEL_DATA received for a closed channel.
In any case the mapper never sends `CH_DATA` after it has sent or received CHANNEL_CLOSE:
the output is then `NO_CHANNEL` and nothing goes on the wire.
So "CH_DATA accepted after CH_CLOSE" cannot be observed with the current alphabet.
It would need an input that reuses the last server channel id after close.

## Limits of the pattern language

Output tokens are compared as a set,
so the order of messages within one step's output cannot be checked.
For example `DISCONNECT+CH_DATA` (data after disconnect) looks the same as `CH_DATA+DISCONNECT`,
and a server KEXINIT followed in the same step by a forbidden message looks the same as the reverse order.
The patterns therefore only check order across steps.
`MSG<n>` outputs cannot be listed in advance,
so "any server message" in the DISCONNECT patterns means any of the 25 named messages.
