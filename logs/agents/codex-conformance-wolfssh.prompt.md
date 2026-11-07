RFC conformance check of the wolfSSH 1.6.0 server message dispatcher (open-source library, running in our own local Docker test target on 127.0.0.1).

Read: results/catalogue/verified-5.json (wolfssh entries), catalogue/ssh/KEX-SERVER-SENDS-NON-KEX.json, literature/ssh-rfc-notes.md (RFC 4253 §7.1), targets/wolfssh/, scripts/replay.py.

Observed on our test server: during a key re-exchange (after the server has sent its KEXINIT and before it has sent NEWKEYS), a USERAUTH_REQUEST from the client is answered with USERAUTH_FAILURE. RFC 4253 §7.1 says that between sending KEXINIT and sending NEWKEYS a party MUST NOT send messages other than numbers 1–49. The model also shows USERAUTH_REQUEST being processed without a prior SERVICE_REQUEST.

1. Reproduce with 
wolfssh: KEXINIT KEX30 NEWKEYS KEXINIT UA_NONE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  KEXINIT          -> KEXINIT
  UA_NONE          -> UA_FAILURE
    < KEXINIT            14ddca3fc95feb7431f4ee74c28e8356e3000001446d6c6b656d3736387832353531392d73686132
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    > KEX30              1e00000020d03422052c1714f51820e111be1e1309e736e8ee95004ced86392d5f1825d448
    < KEX31              1f000000680000001365636473612d736861322d6e69737470323536000000086e69737470323536
    < NEWKEYS            15
    > NEWKEYS            15
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    < KEXINIT            1488bf25858d2b3dc462b13d1581cba8730000011a6d6c6b656d3736387832353531392d73686132
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
    < KEXINIT            1435d53afed2f4f2fb08bca273de635898000001446d6c6b656d3736387832353531392d73686132
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    > KEX30              1e00000020f82d431e5f800e7e5516f826fc28cbce4348cb05127c0f8e1572004164e6b508
    < KEX31              1f000000680000001365636473612d736861322d6e69737470323536000000086e69737470323536
    < NEWKEYS            15
    > NEWKEYS            15
    > SERVICE_REQUEST    050000000c7373682d7573657261757468
    < SERVICE_ACCEPT     060000000c7373682d7573657261757468
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    < KEXINIT            14deb21b09e759e5b701123d07567d4e000000011a6d6c6b656d3736387832353531392d73686132
    > UA_REQUEST         3200000004746573740000000e7373682d636f6e6e656374696f6e0000000870617373776f726400
    < UA_FAILURE         330000000870617373776f726400

wolfssh: KEXINIT KEX30 NEWKEYS UA_NONE
  deterministic over 3: True
  KEXINIT          -> NO_RESP
  KEX30            -> KEX31+NEWKEYS
  NEWKEYS          -> NO_RESP
  UA_NONE          -> UA_FAILURE
    < KEXINIT            1420820bfe75bd618b40780e8660595974000001446d6c6b656d3736387832353531392d73686132
    > KEXINIT            14000000000000000000000000000000000000004b637572766532353531392d7368613235362c63
    > KEX30              1e000000202441ce0a3eb4f9e517990710e1e3720212c3a73d87e4fdb47db25ba58f1a610f
    < KEX31              1f000000680000001365636473612d736861322d6e69737470323536000000086e69737470323536
    < NEWKEYS            15
    > NEWKEYS            15
    > UA_REQUEST         3200000004746573740000000e7373682d636f6e6e656374696f6e000000046e6f6e65
    < UA_FAILURE         330000000870617373776f726400, and the same words on openssh and golang-xcrypto for comparison. Report the outputs.
2. In the wolfSSH source at the tag matching targets/wolfssh (https://github.com/wolfSSL/wolfssh; download into /tmp/claude-1000/-home-lumberj3ck-code-probe-network-protocols/fe0108b1-bafa-491d-bc25-212277efa855/scratchpad/codex-wolfssh-src, read only), find where incoming messages are dispatched while a key exchange is in progress (e.g. DoPacket, isKeying flags) and where USERAUTH_REQUEST is accepted relative to the service request. Give file:line and short quotes. State plainly whether the code checks the key-exchange state before handling message numbers ≥ 50, and whether it checks that ssh-userauth was requested.
3. Conformance verdict only: which RFC 4253 / 4252 requirement is or is not met. Do not analyse attacks.

Write findings/CANDIDATE-003-wolfssh-non-kex-during-rekey.md (semantic line breaks): observation, replay outputs, source references, conformance verdict, confidence. Do not edit src/, tests/, docs/ or targets/.
