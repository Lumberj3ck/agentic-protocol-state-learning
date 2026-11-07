# CANDIDATE-004: MINA SSHD service request after authentication abandons channel routing

## Observation

Reproduced on 2026-11-07 against the local Docker targets, published only on `127.0.0.1` by `smlearn.testbed`.
Apache MINA SSHD 2.20.1 accepts a transport `SSH_MSG_SERVICE_REQUEST` for `ssh-connection` after successful authentication and an established session channel.
It installs a fresh connection service, leaving the earlier channel outside the active service's channel map.
A close for that channel receives no close reply; an exec request receives `CH_FAILURE`.
A subsequently opened channel works.
Requesting `ssh-userauth` instead produces `DISCONNECT+CLOSED`.

The precise source-level finding is replacement of the service reference, not an explicit clearing or removal of entries from the original channel map.
The old service's map keeps its entries at replacement; the new service starts with an empty map.
The replacement path neither closes the old service/channels nor sends `SSH_MSG_CHANNEL_CLOSE` for them.
This describes the immediate transition and routing, not eventual object lifetime or garbage collection.

## Replay procedure and outputs

Each of the following five words was replayed on each of `mina-sshd`, `openssh`, `golang-xcrypto`, and `russh`, with a fresh connection per repetition.
The command pattern was:

```sh
DOCKER_BUILDKIT=0 uv run python scripts/replay.py TARGET \
  'KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN CH_CLOSE' \
  'KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_CONN CH_CLOSE' \
  'KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_CONN CH_REQUEST_EXEC' \
  'KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_CONN CH_OPEN CH_REQUEST_EXEC' \
  'KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_AUTH CH_CLOSE' \
  --reps=3 --trace
```

`A = KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN`.
`SR_CONN` encodes message 5 with service `ssh-connection`; `SR_AUTH` encodes message 5 with service `ssh-userauth`.
`UA_PW_OK` itself requests `ssh-connection` in the authentication request.
`CH_REQUEST_EXEC` requests `true` with `want_reply=true`.
The mapper waits with `timeout=0.8` and `quiet=0.2`; `NO_RESP` is bounded observation, not proof of indefinite silence.
`NO_CONN` means no further packet was sent because the transport was already closed.
The trace printed by `--trace` is from the last repetition.

Target versions: MINA SSHD 2.20.1; OpenSSH_9.2p1 Debian-2+deb12u10 (queried from the built image); golang.org/x/crypto v0.58.0; russh 0.65.1.
The latter two pins are documented in their target READMEs.
OpenSSH's authentication response additionally contains `GLOBAL_REQUEST`.
All 20 target/word combinations were deterministic over three repetitions (60 connections).
The outputs below preserve all step results, including that difference.
Raw replay outputs with traces are also retained for this session under `/tmp/mina-service-replays/{mina-sshd,openssh,golang-xcrypto,russh}.txt`.

### mina-sshd

```text
mina-sshd: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN CH_CLOSE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS
  CH_OPEN          -> CH_OPEN_SUCCESS
  CH_CLOSE         -> CH_CLOSE

mina-sshd: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_CONN CH_CLOSE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS
  CH_OPEN          -> CH_OPEN_SUCCESS
  SR_CONN          -> SERVICE_ACCEPT
  CH_CLOSE         -> NO_RESP

mina-sshd: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_CONN CH_REQUEST_EXEC
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS
  CH_OPEN          -> CH_OPEN_SUCCESS
  SR_CONN          -> SERVICE_ACCEPT
  CH_REQUEST_EXEC  -> CH_FAILURE

mina-sshd: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_CONN CH_OPEN CH_REQUEST_EXEC
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS
  CH_OPEN          -> CH_OPEN_SUCCESS
  SR_CONN          -> SERVICE_ACCEPT
  CH_OPEN          -> CH_OPEN_SUCCESS
  CH_REQUEST_EXEC  -> CH_SUCCESS+CH_EOF+CH_REQUEST+CH_CLOSE

mina-sshd: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_AUTH CH_CLOSE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS
  CH_OPEN          -> CH_OPEN_SUCCESS
  SR_AUTH          -> DISCONNECT+CLOSED
  CH_CLOSE         -> NO_CONN
```

### openssh

```text
openssh: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN CH_CLOSE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS+GLOBAL_REQUEST
  CH_OPEN          -> CH_OPEN_SUCCESS
  CH_CLOSE         -> CH_CLOSE

openssh: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_CONN CH_CLOSE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS+GLOBAL_REQUEST
  CH_OPEN          -> CH_OPEN_SUCCESS
  SR_CONN          -> UNIMPLEMENTED
  CH_CLOSE         -> CH_CLOSE

openssh: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_CONN CH_REQUEST_EXEC
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS+GLOBAL_REQUEST
  CH_OPEN          -> CH_OPEN_SUCCESS
  SR_CONN          -> UNIMPLEMENTED
  CH_REQUEST_EXEC  -> CH_WINDOW_ADJUST+CH_SUCCESS+CH_EOF+CH_REQUEST+CH_CLOSE

openssh: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_CONN CH_OPEN CH_REQUEST_EXEC
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS+GLOBAL_REQUEST
  CH_OPEN          -> CH_OPEN_SUCCESS
  SR_CONN          -> UNIMPLEMENTED
  CH_OPEN          -> CH_OPEN_SUCCESS
  CH_REQUEST_EXEC  -> CH_WINDOW_ADJUST+CH_SUCCESS+CH_EOF+CH_REQUEST+CH_CLOSE

openssh: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_AUTH CH_CLOSE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS+GLOBAL_REQUEST
  CH_OPEN          -> CH_OPEN_SUCCESS
  SR_AUTH          -> UNIMPLEMENTED
  CH_CLOSE         -> CH_CLOSE
```

### golang-xcrypto

```text
golang-xcrypto: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN CH_CLOSE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS
  CH_OPEN          -> CH_OPEN_SUCCESS
  CH_CLOSE         -> CH_CLOSE

golang-xcrypto: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_CONN CH_CLOSE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS
  CH_OPEN          -> CH_OPEN_SUCCESS
  SR_CONN          -> CLOSED
  CH_CLOSE         -> NO_CONN

golang-xcrypto: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_CONN CH_REQUEST_EXEC
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS
  CH_OPEN          -> CH_OPEN_SUCCESS
  SR_CONN          -> CLOSED
  CH_REQUEST_EXEC  -> NO_CONN

golang-xcrypto: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_CONN CH_OPEN CH_REQUEST_EXEC
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS
  CH_OPEN          -> CH_OPEN_SUCCESS
  SR_CONN          -> CLOSED
  CH_OPEN          -> NO_CONN
  CH_REQUEST_EXEC  -> NO_CONN

golang-xcrypto: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_AUTH CH_CLOSE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS
  CH_OPEN          -> CH_OPEN_SUCCESS
  SR_AUTH          -> CLOSED
  CH_CLOSE         -> NO_CONN
```

### russh

```text
russh: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN CH_CLOSE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS
  CH_OPEN          -> CH_OPEN_SUCCESS
  CH_CLOSE         -> CH_CLOSE

russh: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_CONN CH_CLOSE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS
  CH_OPEN          -> CH_OPEN_SUCCESS
  SR_CONN          -> NO_RESP
  CH_CLOSE         -> CH_CLOSE

russh: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_CONN CH_REQUEST_EXEC
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS
  CH_OPEN          -> CH_OPEN_SUCCESS
  SR_CONN          -> NO_RESP
  CH_REQUEST_EXEC  -> CH_SUCCESS+CH_REQUEST+CH_EOF+CH_CLOSE

russh: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_CONN CH_OPEN CH_REQUEST_EXEC
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS
  CH_OPEN          -> CH_OPEN_SUCCESS
  SR_CONN          -> NO_RESP
  CH_OPEN          -> CH_OPEN_SUCCESS
  CH_REQUEST_EXEC  -> CH_SUCCESS+CH_REQUEST+CH_EOF+CH_CLOSE

russh: KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN SR_AUTH CH_CLOSE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  UA_PW_OK         -> UA_SUCCESS
  CH_OPEN          -> CH_OPEN_SUCCESS
  SR_AUTH          -> NO_RESP
  CH_CLOSE         -> CH_CLOSE
```

### MINA packet evidence

The old-channel close sequence ends with these decoded payloads:

```text
> CH_OPEN          5a0000000773657373696f6e000000000020000000008000
< CH_OPEN_SUCCESS  5b00000000000000000020000000008000
> SERVICE_REQUEST  050000000e7373682d636f6e6e656374696f6e
< SERVICE_ACCEPT   060000000e7373682d636f6e6e656374696f6e
> CH_CLOSE         6100000000
(no inbound CHANNEL_CLOSE or transport closure in the observation window)
```

Both original and replacement services allocate server channel ID 0 in these traces.
The mapper also always offers client channel ID 0 when opening a channel (`src/smlearn/ssh/mapper.py:168–169`).
Consequently, the new-open word establishes that the replacement service works, but does not independently test correct simultaneous management of two channels with distinct client IDs.
The decisive old-channel close and exec words have no second open and no such ambiguity.
No close is observed at the service replacement step.
The new exec's later close belongs to the replacement channel.

## MINA source references

Read-only inspection of tag `sshd-2.20.1`, peeled commit `d4bfebc6213b9061d1fcfb62543f679e7ba76ec7`.
Downloaded checkout: `/tmp/claude-1000/-home-lumberj3ck-code-probe-network-protocols/fe0108b1-bafa-491d-bc25-212277efa855/scratchpad/codex-mina-src/upstream`.
All paths below are relative to `sshd-core/src/main/java/org/apache/sshd/`.

- [`common/session/helpers/AbstractSession.java:605–607`](https://github.com/apache/mina-sshd/blob/sshd-2.20.1/sshd-core/src/main/java/org/apache/sshd/common/session/helpers/AbstractSession.java#L605-L607): Dispatch handles message 5 at the transport/session level: `handleServiceRequest(buffer);`. This applies after authentication too. Channel messages instead reach `currentService.process(cmd, buffer)` at lines 640–643.
- [`common/session/helpers/AbstractSession.java:850–879`](https://github.com/apache/mina-sshd/blob/sshd-2.20.1/sshd-core/src/main/java/org/apache/sshd/common/session/helpers/AbstractSession.java#L850-L879): The request handler checks KEX state, invokes `startService(serviceName, buffer);`, then writes `SSH_MSG_SERVICE_ACCEPT` with the requested name. It has no guard against an already active connection service. Creation failure takes the `disconnect(...SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE...)` branch at line 867.
- [`common/session/helpers/AbstractSession.java:882–890`](https://github.com/apache/mina-sshd/blob/sshd-2.20.1/sshd-core/src/main/java/org/apache/sshd/common/session/helpers/AbstractSession.java#L882-L890): `if (KexState.DONE.equals(state)) { return true; }` permits the tested post-authentication state.
- [`server/session/ServerSessionImpl.java:35–39`](https://github.com/apache/mina-sshd/blob/sshd-2.20.1/sshd-core/src/main/java/org/apache/sshd/server/session/ServerSessionImpl.java#L35-L39): `extends AbstractServerSession`; this concrete class does not override the service-request or service-start logic.
- [`server/session/AbstractServerSession.java:259–290`](https://github.com/apache/mina-sshd/blob/sshd-2.20.1/sshd-core/src/main/java/org/apache/sshd/server/session/AbstractServerSession.java#L259-L290): `Service service = factory == null ? null : factory.create(this);` creates a service for every supported request; `currentService.set(service, factory.getName(), true);` installs it. No previous-service close or channel migration occurs here.
- [`server/session/ServerConnectionServiceFactory.java:61–67`](https://github.com/apache/mina-sshd/blob/sshd-2.20.1/sshd-core/src/main/java/org/apache/sshd/server/session/ServerConnectionServiceFactory.java#L61-L67): `ServerConnectionService service = new ServerConnectionService(abstractSession);` creates a new instance rather than returning the active one.
- [`server/session/ServerConnectionService.java:33–38`](https://github.com/apache/mina-sshd/blob/sshd-2.20.1/sshd-core/src/main/java/org/apache/sshd/server/session/ServerConnectionService.java#L33-L38): The constructor checks only authentication here: `if (!s.isAuthenticated())`. An authenticated session passes; an existing service is not rejected.
- [`common/session/helpers/CurrentService.java:77–86`](https://github.com/apache/mina-sshd/blob/sshd-2.20.1/sshd-core/src/main/java/org/apache/sshd/common/session/helpers/CurrentService.java#L77-L86): `currentService = service;` overwrites the reference, followed by `service.start();`. It does not close the replaced service. Lines 106–110 dispatch subsequent service messages exclusively to the new current service.
- [`common/session/helpers/AbstractConnectionService.java:91–98`](https://github.com/apache/mina-sshd/blob/sshd-2.20.1/sshd-core/src/main/java/org/apache/sshd/common/session/helpers/AbstractConnectionService.java#L91-L98): Each instance owns `channels = new ConcurrentHashMap<>();` and `nextChannelId = new AtomicLong(0L);`. Thus replacement starts with no old channels and resets allocation to zero.
- [`common/session/helpers/AbstractConnectionService.java:401–415`](https://github.com/apache/mina-sshd/blob/sshd-2.20.1/sshd-core/src/main/java/org/apache/sshd/common/session/helpers/AbstractConnectionService.java#L401-L415): Registration invokes `channel.init(this, session, channelId);` and `channels.put(channelId, channel);`, associating the original channel with its original service. Normal removal is `channels.remove(channelId)` in `unregisterChannel` at lines 434–438; replacement does not call it.
- [`common/session/helpers/AbstractConnectionService.java:639–660`](https://github.com/apache/mina-sshd/blob/sshd-2.20.1/sshd-core/src/main/java/org/apache/sshd/common/session/helpers/AbstractConnectionService.java#L639-L660): Close/request processing first looks up the recipient in the active service; on a null result it returns. Only a found channel reaches `channel.handleClose();` or `channel.handleRequest(buffer);`.
- [`common/session/helpers/AbstractConnectionService.java:701–719`](https://github.com/apache/mina-sshd/blob/sshd-2.20.1/sshd-core/src/main/java/org/apache/sshd/common/session/helpers/AbstractConnectionService.java#L701-L719): Lookup uses `Channel channel = channels.get(recipient);`. If absent, it invokes `handler.handleUnknownChannelCommand(this, cmd, recipient, buffer);`.
- [`common/session/helpers/DefaultUnknownChannelReferenceHandler.java:59–96`](https://github.com/apache/mina-sshd/blob/sshd-2.20.1/sshd-core/src/main/java/org/apache/sshd/common/session/helpers/DefaultUnknownChannelReferenceHandler.java#L59-L96): `boolean wantReply = false;` remains false for CHANNEL_CLOSE through `default: // do nothing`. CHANNEL_REQUEST reads its want-reply flag and invokes `sendFailureResponse` when true; the handler then returns null. Lines 109–111 construct and send `SSH_MSG_CHANNEL_FAILURE`.
- [`common/BaseBuilder.java:146–147`](https://github.com/apache/mina-sshd/blob/sshd-2.20.1/sshd-core/src/main/java/org/apache/sshd/common/BaseBuilder.java#L146-L147): The default unknown-channel handler is `DefaultUnknownChannelReferenceHandler.INSTANCE`; the local target uses the default server setup without overriding it.
- [`common/session/helpers/AbstractConnectionService.java:388–393`](https://github.com/apache/mina-sshd/blob/sshd-2.20.1/sshd-core/src/main/java/org/apache/sshd/common/session/helpers/AbstractConnectionService.java#L388-L393): Normal service closing includes `.parallel(toString(), getChannels())`. Replacing `CurrentService` never invokes this close path for the previous service.
- [`server/session/AbstractServerSession.java:317–330`](https://github.com/apache/mina-sshd/blob/sshd-2.20.1/sshd-core/src/main/java/org/apache/sshd/server/session/AbstractServerSession.java#L317-L330): Initial authentication success sets authentication and invokes `startService(authService, buffer);` before writing the success packet. The connection service was already installed by the time the original channel opens.
- [`server/session/ServerUserAuthService.java:86–92`](https://github.com/apache/mina-sshd/blob/sshd-2.20.1/sshd-core/src/main/java/org/apache/sshd/server/session/ServerUserAuthService.java#L86-L92): `if (s.isAuthenticated()) { throw new SshException("Session already authenticated"); }` explains why repeated SR_AUTH fails creation and the request handler disconnects instead of accepting it.

## Conformance verdict

The local [RFC notes](../literature/ssh-rfc-notes.md) sections “Service request after the key exchange”, “Success only once, then ignored”, and “Channel close must be answered” provide the starting rules.
The primary RFC text was checked directly as well.

**Accepting SERVICE_REQUEST after authentication is not, by itself, a demonstrated MUST violation.**
[RFC 4253 §10](https://www.rfc-editor.org/rfc/rfc4253.html#section-10) defines the request/accept exchange for supported, permitted services and requires disconnection on rejection.
It also keeps transport messages under transport processing after a service starts.
It neither explicitly prohibits a later request nor defines replacing an already running connection service and discarding its channel routing.
Therefore, the accept packet uses a defined transport mechanism, while its interpretation as a reset of the active connection protocol is not defined by these RFCs.
Acceptance alone should not be reported as an unequivocal violation.

[RFC 4252 §1](https://www.rfc-editor.org/rfc/rfc4252.html#section-1) names the authentication service `ssh-userauth`.
[RFC 4252 §5.1](https://www.rfc-editor.org/rfc/rfc4252.html#section-5.1) requires a single authentication success, recommends silently ignoring later authentication requests, and requires subsequent non-authentication messages to pass to the higher-level service.
These rules establish the authenticated service progression; they do not define a new authentication phase or channel reset upon transport message 5.
In particular, a transport SERVICE_REQUEST is not an SSH_MSG_USERAUTH_REQUEST, and the silent-ignore recommendation for authentication requests is not an unambiguous prohibition on accepting SR_CONN.
RFC 4252 §5.3 additionally states that the requested service starts after authentication succeeds.
There is no need for a further SR_CONN to start the connection service in this exchange.

**Abandoning an established channel without the close exchange, then ignoring its CHANNEL_CLOSE while the transport remains alive, is inconsistent with RFC 4254 §5.3.**
The decisive normative fragment is “a party MUST send back an SSH_MSG_CHANNEL_CLOSE unless it has already sent this message for the channel”.
[RFC 4254 §5.3](https://www.rfc-editor.org/rfc/rfc4254.html#section-5.3) also defines completion of closure by sending and receiving the close message before channel-number reuse.
Here the channel opened successfully, no earlier server close was observed, and MINA sends no reply to the client's close.
The source explains the missing reply deterministically through replacement and unknown-channel handling.
An internal change of service object is not a protocol channel-close exchange.
The same source resets server channel allocation, and the new-open trace shows reuse of server ID 0 before the original close exchange completed; the mapper's repeated client ID limits independent conclusions from that word.
The close-reply failure does not depend on this new-open word.

The comparison targets are behavioural controls, not normative authorities.
OpenSSH returns UNIMPLEMENTED and preserves the channel.
Go closes the transport on either extra service request.
Russh gives no immediate response to either extra service request and preserves the channel, including its close reply and successful exec handling.
The local RFC notes explicitly flag uncertainty about whether repeated service requests answered with UNIMPLEMENTED count as rejection under §10 or unexpected messages under §11.4.
No general conformance judgment about those comparison implementations is made here.
The SR_AUTH disconnection is a separate control that terminates the transport, unlike the accepted SR_CONN path.

## Confidence and limits

High confidence in the MINA observation and immediate source mechanism: five words, three repetitions each, decoded packet traces, and matching code at the exact release tag.
High confidence in the RFC 4254 §5.3 close-reply inconsistency on the still-live accepted-service path.
Acceptance alone remains a specification interpretation with no explicit prohibition identified in the cited sections.
The finite replay timeout cannot establish permanent silence by itself; the source's no-response branch supplies the stronger explanation.
No claim is made about eventual cleanup, retained resources, or behaviour beyond these local target configurations.
Only this finding was added to the repository; no files in `src/`, `tests/`, `docs/`, or `targets/` were changed.
