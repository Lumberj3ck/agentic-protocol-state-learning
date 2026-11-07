RFC conformance check of Apache MINA SSHD 2.20.1 service handling (open-source library, running in our own local Docker test target targets/mina-sshd on 127.0.0.1).

Observed with scripts/replay.py (deterministic over 3 runs), A = "KEXINIT KEX30 NEWKEYS SR_AUTH UA_PW_OK CH_OPEN":
- A CH_CLOSE -> CH_CLOSE (normal)
- A SR_CONN CH_CLOSE -> SERVICE_ACCEPT, then no reply to CH_CLOSE
- A SR_CONN CH_REQUEST_EXEC -> SERVICE_ACCEPT, CH_FAILURE
- A SR_CONN CH_OPEN CH_REQUEST_EXEC -> SERVICE_ACCEPT, CH_OPEN_SUCCESS, CH_SUCCESS+... (new channel works)
- A SR_AUTH CH_CLOSE -> connection closed
So after authentication a SERVICE_REQUEST for "ssh-connection" is accepted and the previously open channel no longer responds.

1. Reproduce these with , and compare the same words on openssh, golang-xcrypto and russh.
2. In the MINA SSHD source at tag sshd-2.20.1 (https://github.com/apache/mina-sshd; download into /tmp/claude-1000/-home-lumberj3ck-code-probe-network-protocols/fe0108b1-bafa-491d-bc25-212277efa855/scratchpad/codex-mina-src, read only), find how SSH_MSG_SERVICE_REQUEST is handled after authentication (e.g. AbstractSession / ServerSessionImpl handleServiceRequest, currentService, ConnectionService creation) and what happens to the existing connection service and its channels. Give file:line and short quotes. Are existing channels closed, kept, or dropped from the channel map? Is any CHANNEL_CLOSE sent for them?
3. Conformance verdict only, citing RFC 4253 §10 and RFC 4252 §§1, 5.1 (via literature/ssh-rfc-notes.md and the RFC text): is accepting this request defined behaviour, and is dropping channels without CHANNEL_CLOSE consistent with RFC 4254 §5.3? Do not analyse attacks.

Write findings/CANDIDATE-004-mina-sshd-service-request-after-auth.md (semantic line breaks): observation, replay outputs, source references, conformance verdict, confidence. Do not edit src/, tests/, docs/ or targets/.
