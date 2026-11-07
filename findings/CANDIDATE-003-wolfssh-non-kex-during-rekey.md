# CANDIDATE-003: wolfSSH sends USERAUTH_FAILURE during rekey

## Context: related upstream work (checked 2026-11-07)

- wolfSSH PR #1200 (merged 2026-08-28, "fix: reject service messages while keying") already enforces RFC 4253 §7.1 for SERVICE_REQUEST/SERVICE_ACCEPT between KEXINIT and NEWKEYS ("Issue: F-10569", an internal tracker).
  This finding is the part of the same rule that fix does not cover: user-authentication and channel messages during a rekey.
- Issue #1287 (reported 2026-09-30 via tlspuffin differential fuzzing, rated "Severity: Low" by the reporter, fixed in `91cb9ad` on 2026-10-12) is the auth-without-service-request behaviour our model also shows; we rediscovered it independently.
- No public wolfSSH issue or PR about user-auth or channel messages during a rekey was found (searched issues and PRs for rekey/KEXINIT/keying/7.1). An internal report cannot be ruled out.

## Update: still present on wolfSSH master (checked 2026-11-07)

Built `targets/wolfssh-master` from master commit `d043c6947787a428c288e4724be092e95dcf2554` (same server program and wolfSSL 5.9.4) and replayed side by side with 1.6.0
([`results/seqnr/wolfssh-release-vs-master.txt`](../results/seqnr/wolfssh-release-vs-master.txt), all deterministic over 3 runs).

| Word (after the initial key exchange) | 1.6.0 | master `d043c69` |
|---|---|---|
| `UA_NONE` with no SERVICE_REQUEST | UA_FAILURE | DISCONNECT (fixed upstream in `91cb9ad`, 2026-10-12, issue #1287, unreleased) |
| `SR_AUTH KEXINIT UA_PW_NOK` | KEXINIT, UA_FAILURE | KEXINIT, UA_FAILURE |
| `SR_AUTH KEXINIT UA_PW_OK` | KEXINIT, **UA_SUCCESS** | KEXINIT, **UA_SUCCESS** |
| `SR_AUTH UA_PW_OK KEXINIT CH_OPEN` | KEXINIT, **CH_OPEN_SUCCESS** | KEXINIT, **CH_OPEN_SUCCESS** |

So the "authentication without a service request" part is an independent rediscovery of a bug wolfSSH fixed on master 26 days earlier,
while the RFC 4253 §7.1 part is still present on master and is broader than first measured:
between its rekey KEXINIT and its NEWKEYS, wolfSSH completes user authentication and opens channels.
The master dispatcher (`IsMessageAllowedServer`) now rejects SERVICE_REQUEST while the peer is keying, but still admits messages ≥ 50 after the service request.

Same word `... UA_PW_OK KEXINIT CH_OPEN KEX30 NEWKEYS` on other servers:
OpenSSH and Apache MINA SSHD hold the reply and send `KEX31+NEWKEYS+CH_OPEN_SUCCESS` after their NEWKEYS (compliant);
Go x/crypto/ssh and russh close the connection; only wolfSSH answers before its NEWKEYS.

## Observation

On 2026-11-07, wolfSSH 1.6.0 reproduced both catalogue observations in `results/catalogue/verified-5.json`.
After completing the initial exchange, the client sends another KEXINIT and receives the server KEXINIT.
Before either side completes that rekey, a USERAUTH_REQUEST produces USERAUTH_FAILURE (message 51).
This happens both for `none` without a preceding service request and for an incorrect password after `ssh-userauth` was requested and accepted.
The latter control separates the rekey behavior from service-request ordering.
Outside rekey, `none` also produces USERAUTH_FAILURE without a prior SERVICE_REQUEST.
Processing a request here does not mean granting authentication: all observed authentication replies are failures.

All targets ran in local Docker containers published only on 127.0.0.1, using `scripts/replay.py`.
The mapper uses a 0.8-second timeout and a 0.2-second quiet interval.
Each word was replayed on three fresh connections.
Determinism refers to output tokens, not random cookies or ephemeral keys.
Target metadata identifies wolfSSH 1.6.0 with wolfSSL 5.9.4, OpenSSH from Debian bookworm-slim, and golang.org/x/crypto v0.58.0.
These are the local target definitions, not the separate OpenSSH Alpine model in the catalogue.

## Replay outputs

Commands (one invocation per target, with TARGET replaced by wolfssh, openssh, or golang-xcrypto):

```sh
DOCKER_CONFIG=/tmp/wolfssh-docker uv run python scripts/replay.py TARGET \
  'KEXINIT KEX30 NEWKEYS KEXINIT UA_NONE' \
  'KEXINIT KEX30 NEWKEYS SR_AUTH KEXINIT UA_PW_NOK' \
  'KEXINIT KEX30 NEWKEYS UA_NONE' --reps=3 --trace
```

The complete printed replay outputs follow.
Hex traces are payload prefixes limited to 80 hex characters by the replay script, from the last repetition.
`>` means client to server; `<` means server to client.
`CLOSED` is an observed transport closure, not a decoded SSH disconnect message.

```text
wolfssh: KEXINIT KEX30 NEWKEYS KEXINIT UA_NONE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  KEXINIT          -> KEXINIT
  UA_NONE          -> UA_FAILURE
    < KEXINIT            147a975b0602ff76a08d23b1ee151c9b7a000001446d6c6b656d3736387832353531392d73686132
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    > KEX30              1e00000020aa275b0b957ff752bdde3076cf253ff64cd13f0013c300581ff42b0e36c4896b
    < KEX31              1f000000680000001365636473612d736861322d6e69737470323536000000086e69737470323536
    < NEWKEYS            15
    > NEWKEYS            15
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    < KEXINIT            14bc5a1cca54bd2955fb25845a6ba25b890000011a6d6c6b656d3736387832353531392d73686132
    > UA_REQUEST         3200000004746573740000000e7373682d636f6e6e656374696f6e000000046e6f6e65
    < UA_FAILURE         330000000870617373776f726400

wolfssh: KEXINIT KEX30 NEWKEYS SR_AUTH KEXINIT UA_PW_NOK
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  KEXINIT          -> KEXINIT
  UA_PW_NOK        -> UA_FAILURE
    < KEXINIT            1485310e9aff9b3f61a10d5a6f8223ddc7000001446d6c6b656d3736387832353531392d73686132
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    > KEX30              1e00000020da826d708d9627a36bfea9f3442b1066997a4411219902a97dd138e03ad0db54
    < KEX31              1f000000680000001365636473612d736861322d6e69737470323536000000086e69737470323536
    < NEWKEYS            15
    > NEWKEYS            15
    > SERVICE_REQUEST    050000000c7373682d7573657261757468
    < SERVICE_ACCEPT     060000000c7373682d7573657261757468
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    < KEXINIT            14d6b2593fc54ce65800979eba7a4253ef0000011a6d6c6b656d3736387832353531392d73686132
    > UA_REQUEST         3200000004746573740000000e7373682d636f6e6e656374696f6e0000000870617373776f726400
    < UA_FAILURE         330000000870617373776f726400

wolfssh: KEXINIT KEX30 NEWKEYS UA_NONE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  UA_NONE          -> UA_FAILURE
    < KEXINIT            140ab00952d0139c4cc6baa812d88998c7000001446d6c6b656d3736387832353531392d73686132
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    > KEX30              1e0000002036a7ecc2c8c84516678f30a75b56d3fde3694ae189b3c6690c724840a14cf229
    < KEX31              1f000000680000001365636473612d736861322d6e69737470323536000000086e69737470323536
    < NEWKEYS            15
    > NEWKEYS            15
    > UA_REQUEST         3200000004746573740000000e7373682d636f6e6e656374696f6e000000046e6f6e65
    < UA_FAILURE         330000000870617373776f726400
```

```text
openssh: KEXINIT KEX30 NEWKEYS KEXINIT UA_NONE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  KEXINIT          -> UNIMPLEMENTED
  UA_NONE          -> UNIMPLEMENTED
    < KEXINIT            145ba617b2ef6a3649a78acd9430780a620000013d736e747275703736317832353531392d736861
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    > KEX30              1e00000020fa2f71e2e1cb0d112181ed3310e3aacf6f84e5bc3b9b404c41fa154ea2a74069
    < KEX31              1f000000330000000b7373682d6564323535313900000020728a7740d15fa7e4fc1817e8e9282b21
    < NEWKEYS            15
    > NEWKEYS            15
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    < UNIMPLEMENTED      0300000000
    > UA_REQUEST         3200000004746573740000000e7373682d636f6e6e656374696f6e000000046e6f6e65
    < UNIMPLEMENTED      0300000001

openssh: KEXINIT KEX30 NEWKEYS SR_AUTH KEXINIT UA_PW_NOK
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  KEXINIT          -> UNIMPLEMENTED
  UA_PW_NOK        -> UA_FAILURE
    < KEXINIT            14056f40dc34bc888737cff5b951b1bd990000013d736e747275703736317832353531392d736861
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    > KEX30              1e000000200cf18504f88bed9c030f426e72e8faec60ebf6ce3498a32ff99f23f0a483550d
    < KEX31              1f000000330000000b7373682d6564323535313900000020728a7740d15fa7e4fc1817e8e9282b21
    < NEWKEYS            15
    > NEWKEYS            15
    > SERVICE_REQUEST    050000000c7373682d7573657261757468
    < SERVICE_ACCEPT     060000000c7373682d7573657261757468
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    < UNIMPLEMENTED      0300000001
    > UA_REQUEST         3200000004746573740000000e7373682d636f6e6e656374696f6e0000000870617373776f726400
    < UA_FAILURE         33000000127075626c69636b65792c70617373776f726400

openssh: KEXINIT KEX30 NEWKEYS UA_NONE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  UA_NONE          -> UNIMPLEMENTED
    < KEXINIT            1472cdd8a15b50e4e70c8b849949f763710000013d736e747275703736317832353531392d736861
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    > KEX30              1e000000209a52ecdcde34ce96a95ffab768be43a2ea8bff51f86d16dc7c660b0b174af55b
    < KEX31              1f000000330000000b7373682d6564323535313900000020728a7740d15fa7e4fc1817e8e9282b21
    < NEWKEYS            15
    > NEWKEYS            15
    > UA_REQUEST         3200000004746573740000000e7373682d636f6e6e656374696f6e000000046e6f6e65
    < UNIMPLEMENTED      0300000000
```

```text
golang-xcrypto: KEXINIT KEX30 NEWKEYS KEXINIT UA_NONE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  KEXINIT          -> KEXINIT
  UA_NONE          -> CLOSED
    < KEXINIT            143d7623747ac4caf599f01b7a7d3ea1d3000000d46d6c6b656d3736387832353531392d73686132
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    > KEX30              1e00000020251e19c3ba9ad678c1fab7f990ac8cca0b3c90b21f549a1fbf7198bbe1917933
    < KEX31              1f000000330000000b7373682d6564323535313900000020588c47e6fa0b14f9f30a0357509d74be
    < NEWKEYS            15
    > NEWKEYS            15
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    < KEXINIT            142aeed4ccbce51356d6293a7dc66c5d00000000b76d6c6b656d3736387832353531392d73686132
    > UA_REQUEST         3200000004746573740000000e7373682d636f6e6e656374696f6e000000046e6f6e65

golang-xcrypto: KEXINIT KEX30 NEWKEYS SR_AUTH KEXINIT UA_PW_NOK
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  SR_AUTH          -> SERVICE_ACCEPT
  KEXINIT          -> KEXINIT
  UA_PW_NOK        -> CLOSED
    < KEXINIT            1498e7cbb7eac322f21223100593c21dfd000000d46d6c6b656d3736387832353531392d73686132
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    > KEX30              1e0000002090ef3068b7764a6c45e7800e6f6018e27e6c1b748466851162ca5bd9fa7bc715
    < KEX31              1f000000330000000b7373682d6564323535313900000020588c47e6fa0b14f9f30a0357509d74be
    < NEWKEYS            15
    > NEWKEYS            15
    > SERVICE_REQUEST    050000000c7373682d7573657261757468
    < SERVICE_ACCEPT     060000000c7373682d7573657261757468
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    < KEXINIT            140ff16295e37745c4ec90d341a4a37360000000b76d6c6b656d3736387832353531392d73686132
    > UA_REQUEST         3200000004746573740000000e7373682d636f6e6e656374696f6e0000000870617373776f726400

golang-xcrypto: KEXINIT KEX30 NEWKEYS UA_NONE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  UA_NONE          -> CLOSED
    < KEXINIT            140f719e2b722f3619f313048e3363694f000000d46d6c6b656d3736387832353531392d73686132
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    > KEX30              1e00000020d21e7cb3998cc21a4ef1b1ec10fbf6fdc2c35add79e7da271eae111170f2e314
    < KEX31              1f000000330000000b7373682d6564323535313900000020588c47e6fa0b14f9f30a0357509d74be
    < NEWKEYS            15
    > NEWKEYS            15
    > UA_REQUEST         3200000004746573740000000e7373682d636f6e6e656374696f6e000000046e6f6e65
```

OpenSSH answers the attempted rekey with UNIMPLEMENTED, so its subsequent password failure does not occur inside an observed server KEXINIT–NEWKEYS interval.
Go answers the rekey with KEXINIT and then closes on the authentication request; no USERAUTH_FAILURE is observed in that interval.
These comparisons describe these words only, not general conformance of either implementation.

## Source references

Source: [wolfSSL/wolfssh, v1.6.0-stable](https://github.com/wolfSSL/wolfssh/tree/v1.6.0-stable).
A fresh tag archive was downloaded from `https://codeload.github.com/wolfSSL/wolfssh/tar.gz/refs/tags/v1.6.0-stable` and extracted under the requested scratch directory at `candidate003-pristine/wolfssh-1.6.0-stable/`.
The source was inspected without edits.
Tag archive SHA-256: `e345b580643af6715a4293ed7bab4e99ea562bb379adb8898eeae55c38b12f56`.
The release archive SHA-256 is `5bd4425d40a451607c78fcab2629242751e6cc59b5c9ebdfa4805fc704e1bfef`, matching `targets/wolfssh/Dockerfile`.
The tag and release archives contain byte-identical `src/internal.c` (SHA-256 `81d23e67893f75022994fb4e5145e6eb70d820014ffc273283643fce9ae68649`).
Line numbers below refer to the freshly extracted tag.

- `src/internal.c:14020`, in `DoPacket`: `msgAllowed = IsMessageAllowed(ssh, msg, WS_MSG_RECV);`.
  At `src/internal.c:14179–14182`, `case MSGID_USERAUTH_REQUEST:` directly calls `DoUserAuthRequest(ssh, buf + idx, payloadSz, &payloadIdx)`.
- `src/internal.c:1032–1033`: the general strict-KEX receive guard is conditional on `ssh->useStrictKex && !ssh->initialKexDone`.
  It covers the initial exchange, not this rekey.
- `src/internal.c:806–807`, in `IsMessageAllowedServer`: `if (MSGIDLIMIT_TRANS(msg)) {` encloses `if (ssh->isKeying & WOLFSSH_PEER_IS_KEYING) {`.
  `wolfssh/internal.h:2004–2011` defines the transport range as 1–49.
  Thus this keying-state branch does not cover USERAUTH_REQUEST (50).
- `src/internal.c:845–850`: `if (ssh->acceptState < ACCEPT_KEYED)` rejects messages above `MSGID_KEXDH_GEX_REQUEST` only before the initial keyed state.
  `src/internal.c:853–876` checks authentication completion and rejects server-only authentication messages with `msg > MSGID_USERAUTH_REQUEST`, leaving request 50 allowed.
  **There is no rekey-state gate before dispatching messages numbered 50 or higher.**
  Authentication-state restrictions still apply; this is not a claim that every such message is accepted.
- `src/internal.c:6636`: `ssh->isKeying |= WOLFSSH_PEER_IS_KEYING;` records receipt of KEXINIT.
  `src/internal.c:6962–6964` calls `SendKexInit(ssh)` if self-keying was not already set.
  `src/internal.c:15530` sets `WOLFSSH_SELF_IS_KEYING` once KEXINIT is sent or queued.
  `src/internal.c:18960` clears that flag in the NEWKEYS send path.
- `src/internal.c:9662–9691`, `DoServiceRequest`, validates the requested name as `ssh-userauth` and records `ssh->clientState = CLIENT_USERAUTH_REQUEST_DONE;` at line 9687.
  `src/ssh.c:756–778` normally waits for that state and sends SERVICE_ACCEPT.
  The waiting loop calls `DoReceive(ssh)`, which can dispatch authentication requests while still waiting.
- `src/internal.c:11802–11937`, `DoUserAuthRequest`, parses the username, requested higher-level service, and authentication method.
  The service check at `src/internal.c:11829–11830` compares against `ID_SERVICE_CONNECTION`; this is the service field inside USERAUTH_REQUEST, not evidence that `ssh-userauth` was previously requested.
  The password handler is called at line 11903; the unsupported-method branch calls `SendUserAuthFailureCount(ssh, 0, countIt)` at line 11927.
  **Neither this handler nor its dispatcher admission check requires a previous `ssh-userauth` SERVICE_REQUEST.**
- `src/internal.c:9848`: `SendUserAuthFailureCount` calls `SendUserAuthFailure(ssh, partialSuccess)`.
  `src/internal.c:22681` writes `MSGID_USERAUTH_FAILURE`; line 22694 calls `wolfSSH_SendPacket(ssh)`.
  This failure-send function has no keying-state check or deferral.

## Conformance verdict

**Confirmed RFC 4253 §7.1 MUST NOT violation in both wolfSSH rekey words.**
The requirement constrains what a party sends from its KEXINIT until its NEWKEYS.
The permitted categories are transport generic messages 1–19 with SERVICE_REQUEST and SERVICE_ACCEPT excluded, negotiation messages 20–29 with further KEXINIT excluded, and key-exchange method messages 30–49.
USERAUTH_FAILURE is 51 and is outside those categories.
The traces place the server KEXINIT and failure in separate steps with no intervening server NEWKEYS, avoiding the catalogue's within-step ordering limitation.
RFC 4253 §9 also says re-exchange is processed identically to the initial exchange except for the unchanged session identifier.

The client authentication request (50) sent after its rekey KEXINIT likewise violates the client's §7.1 send restriction.
That deliberately out-of-sequence stimulus does not permit the server to send message 51 during its own prohibited interval.
The §7.1 requirement to process messages in flight before receiving the peer KEXINIT does not explain this case: the server has already received the peer KEXINIT and replied with its own.
The finding is about the forbidden server response, not a claim that §7.1 universally mandates disconnecting on unexpected input.

**Authentication before SERVICE_REQUEST is confirmed behavior, but no explicit RFC 4252/4253 MUST or SHOULD rejection requirement is established for it.**
RFC 4253 §10 describes requesting a service after key exchange, and RFC 4252 §1 names the authentication service `ssh-userauth`.
The behavior departs from that described service ordering.
The catalogue labels `UA-BEFORE-SR-AUTH` SHOULD as a modelling choice; that label is not a quoted normative RFC SHOULD.
It should not be promoted to a separate mandatory rejection violation.

RFC 4252 §4 requires rejecting `none` unless access without authentication is intended.
The observed failures meet that rejection requirement for this password-only target.
RFC 4252 §5.1 specifies USERAUTH_FAILURE for a rejected authentication request, and the observed payload encodes the method list `password` with partial success false.
Those response semantics do not override RFC 4253 §7.1's restriction on when message 51 may be sent.
The no-rekey control alone establishes no §7.1 violation.

Normative references: [RFC 4253 §§7.1, 9, 10](https://www.rfc-editor.org/rfc/rfc4253.html#section-7.1), [RFC 4252 §§1, 4, 5.1](https://www.rfc-editor.org/rfc/rfc4252.html#section-4).
The normative text and catalogue interpretation were read in `literature/ssh-rfc-notes.md` and `catalogue/ssh/KEX-SERVER-SENDS-NON-KEX.json`.

## Confidence

High for the forbidden server response: both variants reproduce identically over three connections, with ordered packet traces and a matching source path.
High for processing authentication without a prior service request: the standalone control and dispatcher checks agree.
The conclusion is confined to these sequences, this configured local target, and RFC conformance.
