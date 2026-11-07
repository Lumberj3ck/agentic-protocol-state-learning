# SSH server state machines: ground truth from the literature

This file collects what published work reports about the state machines of SSH servers,
so that our learned models of OpenSSH, Dropbear and AsyncSSH can be checked against it before we claim anything new.
The normative RFC text is in [ssh-rfc-notes.md](ssh-rfc-notes.md) and is not repeated here.
Section 5 has the summary table.

Basis tags in the table and text:
**[lit]** means a paper or advisory reports it for the named version.
**[code]** means we read the source of the exact version we run and the behaviour follows from it; this is unverified until a model shows it.
**[infer]** means an educated guess from older results or release notes.

## 0. Our targets and how they relate to the literature

- OpenSSH: `debian:bookworm-slim` with `openssh-server`, which bookworm currently ships as `1:9.2p1-2+deb12u10` ([madison](https://qa.debian.org/madison.php?package=openssh-server&table=debian&s=bookworm,bookworm-security,bookworm-updates)).
  Strict KEX was backported in `1:9.2p1-2+deb12u2` (DSA-5586-1) ([Debian tracker](https://security-tracker.debian.org/tracker/CVE-2023-48795), [Debian changelog](https://metadata.ftp-master.debian.org/changelogs/main/o/openssh/oldstable_changelog)).
  The backport is the upstream strict-KEX commit `1edb00c5` ([Debian patch](https://salsa.debian.org/ssh-team/openssh/-/blob/debian/1%259.2p1-2+deb12u10/debian/patches/CVE-2023-48795.patch)).
  No later bookworm upload touches the transport state machine (same changelog).
- Dropbear: Alpine 3.20 ships `dropbear 2024.85-r0`, built from the upstream tarball with no strict-KEX or channel patches ([APKBUILD](https://gitlab.alpinelinux.org/alpine/aports/-/blob/3.20-stable/main/dropbear/APKBUILD)).
  Strict KEX arrived in 2024.84 ([Dropbear CHANGES](https://matt.ucc.asn.au/dropbear/CHANGES)).
- AsyncSSH: `asyncssh==2.17.0` (2 Sep 2024).
  Strict KEX arrived in 2.14.2, and the state machine hardening for CVE-2023-46445/46446 in 2.14.1 ([AsyncSSH changelog](https://github.com/ronf/asyncssh/blob/develop/docs/changes.rst)).

Things that differ from the earlier setups and change what "the same behaviour" means:

- The Radboud mapper did not absorb the server KEXINIT, so in their models the first input of any kind outputs `KEXINIT` ([Verleg, Fig. 5.1](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).
  The SPIN paper says it "cannot yet explain" this ([SPIN 2017, §6.4](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf)); it is just the server's own KEXINIT arriving.
  Our `reset()` absorbs it, so our first step is shifted relative to theirs.
- Every model before 2024 was learned without strict KEX.
  Our mapper offers `kex-strict-c-v00@openssh.com` by default, which changes the initial KEX for all three targets (section 3).
  To reproduce the pre-2024 results, learn a second set of models with `strict_kex=False`.
- Their alphabet had `CH_REQUEST_PTY`, `UA_PK_OK/NOK`, `CH_EDATA` and `CH_WINDOW_ADJUST`; ours has `CH_REQUEST_EXEC` (`true`) and no public-key inputs ([SPIN 2017, Tables 1-3](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf)).
  `exec true` ends on its own, so the server may send `CH_DATA`/`CH_EOF`/`CH_REQUEST`/`CH_CLOSE` by itself; a pty request does not do that.
- Their `ch_none`/`ch_max` mapper outputs correspond to our `NO_CHANNEL`; we have no `ch_max`, because `CH_OPEN` is always sent ([SPIN 2017, §4.2](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf), [mapper spec](../docs/MAPPER-SPEC-SSH.md)).
- Verleg learned each layer on its own, from a fixed prefix and with an atomic `REKEY` symbol ([Verleg, §4.5](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)); we learn all layers together, as Lenaerts and SPIN did.

Notation for input words: they start right after `reset()`.
`HS` stands for `KEXINIT KEX30 NEWKEYS`, and `AUTH` for `HS SR_AUTH UA_PW_OK`.
In every report, the happy flow `HS` gives `NO_RESP`, `KEX31+NEWKEYS`, `NO_RESP`: the server sends its NEWKEYS first, together with KEX31 ([SPIN 2017, §5, footnote 4](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf)).

## 1. Fiterău-Broştean, Lenaerts, Poll, de Ruiter, Vaandrager, Verleg (SPIN 2017) and Verleg (2016)

### Setup

The SPIN paper builds on two theses, Verleg's master thesis and Lenaerts' bachelor thesis ([SPIN 2017, §1](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf)).
It learns servers only, with LearnLib and a mapper built from Paramiko, and starts after the version exchange ([SPIN 2017, §4](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf)).
The full alphabet has 21 inputs:
transport `DISCONNECT, IGNORE, UNIMPL, DEBUG, KEXINIT, KEX30, NEWKEYS, SR_AUTH, SR_CONN`,
auth `UA_NONE, UA_PK_OK, UA_PK_NOK, UA_PW_OK, UA_PW_NOK`,
and connection `CH_OPEN, CH_CLOSE, CH_EOF, CH_DATA, CH_EDATA, CH_WINDOW_ADJUST, CH_REQUEST_PTY` ([SPIN 2017, Tables 1-3](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf)).
The restricted alphabet drops `IGNORE, UNIMPL, DEBUG, DISCONNECT`, password auth, `UA_NONE`, `CH_EDATA` and `CH_WINDOW_ADJUST` (same tables).
OpenSSH was learned with the full alphabet, and Bitvise and DropBear with the restricted one ([SPIN 2017, §5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf)).
So the Dropbear model never saw `IGNORE`, `DEBUG`, `UNIMPLEMENTED`, `DISCONNECT`, `UA_PW_*` or `UA_NONE`.
Verleg's thesis adds `GUESSINIT` (a KEXINIT with `first_kex_packet_follows`) and an atomic `REKEY`, and tests six servers ([Verleg, Tables 4.2-4.5](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).
The models are published, per the paper, at `gitlab.science.ru.nl/pfiteraubrostean/Learning-SSH-Paper` ([SPIN 2017, §5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf)), and as an automata wiki benchmark ([BenchmarkSSH-Fiterau-BrosteanEtAl2017](https://automata.cs.ru.nl/BenchmarkSSH-Fiterau-BrosteanEtAl2017)).

### Model sizes

| Source | Implementation | Alphabet | States |
|---|---|---|---|
| [SPIN 2017, Table 4](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf) | OpenSSH 6.9p1-2 | full (21) | 31 |
| [SPIN 2017, Table 4](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf) | Bitvise 7.23 | restricted | 65 |
| [SPIN 2017, Table 4](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf) | DropBear v2014.65 | restricted | 29 |
| [Lenaerts 2017, §5.1](https://www.cs.ru.nl/bachelors-theses/2017/Toon_Lenaerts___4321219___Improving-protocol-state-fuzzing-of-SSH.pdf) | OpenSSH 6.6p1 | full, all layers | 26 (619 transitions) |
| [Verleg, Figs. 5.1, 5.8, 5.13](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf) | OpenSSH 6.9p1-2 | per layer | 5 transport, 3 auth, 6 connection (as drawn, after simplification) |
| [Verleg, Figs. 5.3, 5.7, 5.12](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf) | Dropbear 2014.65-1 | per layer | 5 transport, 2 auth, 6 connection (as drawn) |
| [Bäumer et al. CCS 2025, Table 3](https://arxiv.org/pdf/2509.10895) | OpenSSH 9.9p2, strict KEX, ECDH | 86 symbols, handshake only | 9 (6 in the key exchange) |

The SPIN paper puts the high state counts down to rekeying (two extra states for every state that allows rekeying), Bitvise buffering, and mapper-generated `ch_none`/`ch_max` outputs ([SPIN 2017, §5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf)).
Our mapper has no `ch_max`, so we should expect fewer states from the channel buffer.
Lenaerts left out of his figure nine states reachable by opening a channel before authentication: they can still authenticate, but they never open a channel and always end in disconnect ([Lenaerts, §5.1](https://www.cs.ru.nl/bachelors-theses/2017/Toon_Lenaerts___4321219___Improving-protocol-state-fuzzing-of-SSH.pdf)).

### Behavioural findings

Security properties:

- All three servers satisfy the security properties:
  no service request is accepted without a completed key exchange, and no channel opens without valid credentials ([SPIN 2017, §6.2, §6.5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf)).
  Verleg found the same for all six servers ([Verleg, Abstract, §5.1.1, §5.2.1](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).

Transport layer:

- OpenSSH 6.9 is "extremely liberal" in parameter negotiation: the client KEXINIT "need not to be sent at all" ([Verleg, §5.1, Fig. 5.1](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).
- In OpenSSH 6.9, once keys are in place and before authentication, `KEXINIT`, `GUESSINIT` and `KEX30` yield `UNIMPL`, `SR_CONN` yields `DISCONNECT`, and `NEWKEYS` closes the connection ([Verleg, Fig. 5.1](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).
- Dropbear 2014.65 requires the client KEXINIT, allows rekeying right after the first KEX, and answers unexpected messages by closing the connection (`OTHER/NO_CONN`) without a DISCONNECT message ([Verleg, Fig. 5.3](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).
- Some servers buffer the SERVICE_ACCEPT for a service request sent during rekeying (Tectia, PowerShell, and Bitvise for all higher-layer replies); Dropbear, OpenSSH and Cisco do not ([Verleg, §5.1, §5.1.1](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf), [SPIN 2017, §5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf)).
  The Dropbear author holds that the RFCs do not allow buffering (Verleg, §5.1).
- Bitvise 6.45 becomes unresponsive when `NEWKEYS` directly follows parameter negotiation (`KEXINIT NEWKEYS`), and Tectia has a similar unresponsive state ([Verleg, Figs. 5.4, 5.6](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).
- Tectia rekeys as soon as it has received `kexinit`, `kex30` and `newkeys`, in any order ([Verleg, §5.1](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).
- Cisco accepts `SR_AUTH` only once and closes the connection on a second one ([Verleg, Fig. 5.2](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).
- `IGNORE` and `DEBUG` never changed state, and neither did `UNIMPL`, except on Dropbear and Tectia ([Verleg, §4.6](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).

Rekeying:

- OpenSSH allows rekeying only in connection-layer states, i.e. after authentication ([SPIN 2017, §5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf), [Verleg, Fig. 5.8](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).
  Before that, `KEXINIT` gives `UNIMPL` and `NEWKEYS` disconnects ([SPIN 2017, §5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf)).
- DropBear is the only one of the three that allows rekeying both before and after authentication ([SPIN 2017, §6.5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf)).
- In OpenSSH, rekeying after authentication is not state-preserving:
  the reply to `SR_AUTH`, `SR_CONN` or `KEX30` changes from `UNIMPL` before the first rekey to `NO_RESP` after it, which splits the model into two sub-clusters ([SPIN 2017, §5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf)).
  Lenaerts found the same on OpenSSH 6.6p1 ("authed" goes to "authed rekeyed", and so on) ([Lenaerts, §6.3](https://www.cs.ru.nl/bachelors-theses/2017/Toon_Lenaerts___4321219___Improving-protocol-state-fuzzing-of-SSH.pdf)).
- OpenSSH 6.9 closes the whole connection on `CH_CLOSE` once any non-open query (including a rekey) has followed `CH_OPEN` ([Verleg, §5.3, Fig. 5.13](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).
  Lenaerts' OpenSSH 6.6p1 model does not show this ([Lenaerts, §5.2](https://www.cs.ru.nl/bachelors-theses/2017/Toon_Lenaerts___4321219___Improving-protocol-state-fuzzing-of-SSH.pdf)).

Authentication layer:

- After a successful authentication, OpenSSH and Bitvise answer further auth requests with `UNIMPL` instead of ignoring them (RFC 4252 SHOULD, Property 11) ([SPIN 2017, §6.5, Table 5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf)).
  Dropbear 2014.65 gives `NO_RESP` there ([Verleg, Fig. 5.7](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).
- OpenSSH breaks the authors' Property 8 (`SR_AUTH` outside the initial state must get accept or disconnect) by answering `UNIMPL` ([SPIN 2017, §6.4, Table 5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf)).
- In OpenSSH, after a failed attempt only password authentication remains allowed ([SPIN 2017, §5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf)).
- OpenSSH and Tectia reject a change of username between attempts ([Verleg, §5.2](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).
- After authentication, OpenSSH sends a `GLOBAL_REQUEST` for `hostkeys-00@openssh.com` ([Verleg, §5.2](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).
- On Dropbear, a valid authentication sent within five milliseconds after an authentication request could wrongly fail, a timing artefact rather than a state ([Verleg, §4.4.1](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).

Connection layer:

- DropBear answers `CH_CLOSE` with `CH_EOF` instead of `CH_CLOSE`, violating RFC 4254 §5.3 (Property 12) ([SPIN 2017, §6.5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf), [Verleg, Fig. 5.12](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).
- OpenSSH and DropBear close the connection on a second pty request on the same channel; only Bitvise allowed several ([SPIN 2017, §5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf), [Verleg, §5.3](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).
- After `CH_EOF`, DropBear stops responding to connection-layer messages, and channel data after EOF closes the connection ([Verleg, §5.3, Fig. 5.12](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).
- PowerShell and Cisco cannot open a second channel after closing the first ([Verleg, §5.3](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf)).

## 2. Follow-up on newer versions: Fiterău-Broştean, Jonsson, Sagonas, Tåquist (NDSS 2023)

This paper encodes the SPIN properties, plus five new ones, as bug-pattern automata and applies them to BitVise 8.49, Dropbear v2020.81 and OpenSSH 8.8p1, with the SPIN mapper ([NDSS 2023, §VII-A, §VIII-B, Table I](https://www.ndss-symposium.org/wp-content/uploads/2023-68-paper.pdf)).
The models are hypotheses after two days of learning, and only Dropbear converged (same, §VIII-B).
It reports no state counts in the text.
Its Table I lists:

- OpenSSH 8.8p1: Rekey Fail Before Auth, Invalid SERVICE_REQUEST_USERAUTH Response, Unignored Auth Request After USERAUTH_SUCCESS, Invalid CHANNEL_CLOSE Response, Missing NEWKEYS.
- BitVise 8.49: Rekey Fail After Auth, Invalid SERVICE_REQUEST_USERAUTH Response, Unignored Auth Request After USERAUTH_SUCCESS, Missing NEWKEYS.
- Dropbear 2020.81: Invalid CHANNEL_CLOSE Response, Missing SERVICE_REQUEST_USERAUTH.

The new findings are described in the text ([NDSS 2023, §VIII-B](https://www.ndss-symposium.org/wp-content/uploads/2023-68-paper.pdf)):

- Dropbear 2020.81 always answers `CH_CLOSE` with `CH_EOF`.
  The developer acknowledged it, and the paper says it was fixed in v2022.82.
- OpenSSH 8.8p1, right after it has sent its NEWKEYS in a rekey, still processes messages under the old keys.
  It answers `CH_OPEN` with `CH_OPEN_SUCCESS`, stays silent on a following `CH_CLOSE`, and sends `CH_CLOSE` only when the client NEWKEYS arrives.
- "Incomplete rekey": OpenSSH and BitVise process upper-layer messages received after the server NEWKEYS and before the client NEWKEYS.
- Dropbear lets authentication proceed straight after the client NEWKEYS, without `SR_AUTH`.
  The developer said this is intentional (Dropbear disregards service requests), i.e. wontfix ([NDSS 2023, §VIII-B, Appendix A](https://www.ndss-symposium.org/wp-content/uploads/2023-68-paper.pdf)).

## 3. Terrapin (Bäumer, Brinkmann, Schwenk, USENIX Security 2024, CVE-2023-48795) and strict KEX

### State-machine behaviour Terrapin relies on

- **RcvIncrease**: a MitM raises the peer's receive sequence number by N by injecting N `IGNORE` messages, or any other message that gets no response, during the unencrypted handshake ([Terrapin, §4.1, Fig. 4a](https://www.usenix.org/system/files/usenixsecurity24-baumer.pdf)).
  It works because RFC 4253 §11.2 requires IGNORE to be accepted at any time.
- **SndIncrease/SndDecrease**: an unrecognised message ID during the handshake makes the peer send `UNIMPLEMENTED`, which raises its send counter; the MitM drops those replies ([Terrapin, §4.1, Figs. 4c, 4d](https://www.usenix.org/system/files/usenixsecurity24-baumer.pdf)).
  **RcvDecrease** and the Snd variants need 2^32 messages and a sequence-number rollover during the handshake (same section).
- Measured server behaviour (same section):
  OpenSSH 9.5p1 detects a sequence-number rollover and terminates, so only RcvIncrease works.
  AsyncSSH 2.13.2 and libssh 0.10.5 allow RcvIncrease but time out before the advanced techniques finish.
  Dropbear 2022.83 disconnects on unknown messages instead of sending `UNIMPLEMENTED`, but allows rollover, so only the Rcv techniques work.
- Prefix truncation: the MitM injects IGNOREs before NEWKEYS and deletes the same number of messages from the start of the secure channel, typically the server's `EXT_INFO` ([Terrapin, §4.2, §5.2](https://www.usenix.org/system/files/usenixsecurity24-baumer.pdf)).
  This is exploitable with ChaCha20-Poly1305 and CBC-EtM, not with AES-CTR plus HMAC (our mapper's cipher) ([Terrapin, Table 1](https://www.usenix.org/system/files/usenixsecurity24-baumer.pdf)).
  So our learner cannot run Terrapin itself, but it can see whether its precondition holds: optional messages tolerated during the initial KEX.

### The strict KEX fix

OpenSSH 9.6 (2023-12-18) terminates the connection on "any unnecessary or unexpected message" during the initial KEX, including DEBUG, and resets the sequence numbers at the end of each key exchange ([OpenSSH 9.6 release notes](https://www.openssh.com/txt/release-9.6)).
The normative text (draft-miller-sshm-strict-kex, PROTOCOL §1.9 at V_9_6_P1) is quoted in [ssh-rfc-notes.md](ssh-rfc-notes.md#strict-kex).
The Terrapin paper calls this the countermeasure that "has since been adopted by various vendors" ([Terrapin, §8](https://www.usenix.org/system/files/usenixsecurity24-baumer.pdf)).

When each target got it:

| Implementation | Strict KEX since | Our version | Source |
|---|---|---|---|
| OpenSSH | 9.6 / 9.6p1; Debian bookworm backport `1:9.2p1-2+deb12u2` | `1:9.2p1-2+deb12u10` | [Terrapin patches](https://terrapin-attack.com/patches.html), [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2023-48795) |
| Dropbear | 2024.84 (Alpine's 2022.83-r4 patched it earlier) | 2024.85 | [Dropbear CHANGES](https://matt.ucc.asn.au/dropbear/CHANGES), [APKBUILD secfixes](https://gitlab.alpinelinux.org/alpine/aports/-/blob/3.20-stable/main/dropbear/APKBUILD) |
| AsyncSSH | 2.14.2 | 2.17.0 | [AsyncSSH changelog](https://github.com/ronf/asyncssh/blob/develop/docs/changes.rst), [Terrapin patches](https://terrapin-attack.com/patches.html) |

How each target enforces it, from the code of the versions we run ([code]):

- OpenSSH: during the initial KEX, every handler not in the KEX dispatch table goes to `kex_protocol_error`, which disconnects with "strict KEX violation" ([kex.c at V_9_6_P1](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/kex.c)).
  Implicit handling of IGNORE/DEBUG/UNIMPLEMENTED is skipped while strict KEX is in force ([packet.c at V_9_6_P1](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/packet.c)).
  A client KEXINIT with sequence number ≠ 0 triggers "KEXINIT was not the first packet".
  The `KEX_INITIAL` flag is cleared only in `kex_input_newkeys`, i.e. when the client NEWKEYS arrives (kex.c).
  DISCONNECT is still processed (packet.c).
- Dropbear 2024.85: strict mode is lifted when Dropbear **sends** its own NEWKEYS (`donefirstkex` is set in `send_msg_newkeys`) ([common-kex.c](https://github.com/mkj/dropbear/blob/DROPBEAR_2024.85/src/common-kex.c), [process-packet.c](https://github.com/mkj/dropbear/blob/DROPBEAR_2024.85/src/process-packet.c)).
  After that, while it waits for the client NEWKEYS, `IGNORE`/`DEBUG`/`UNIMPLEMENTED` are silently accepted.
  Any other message 1-49, apart from SERVICE_REQUEST, SERVICE_ACCEPT and KEXINIT, gets an `UNIMPLEMENTED` reply; anything else exits.
  This is fixed upstream in 2025.88: "Dropbear previously would allow other packets at the end of key exchange prior to receiving the remote peer's NEWKEYS message, which should be forbidden by strict KEX. Reported by Fabian Bäumer." ([Dropbear CHANGES](https://matt.ucc.asn.au/dropbear/CHANGES), [commit 6b0e004](https://github.com/mkj/dropbear/commit/6b0e0041bc5cc8adca0e1ff1823821935e843dbc)).
  A KEXINIT received with `recvseq != 1` exits with "First packet wasn't kexinit" ([commit 6e43be5](https://github.com/mkj/dropbear/commit/6e43be5c7b99dbee49dc72b6f989f29fdd7e9356)).
- AsyncSSH 2.17.0: while the incoming direction is unencrypted, messages 2-4 raise "Strict key exchange violation", and so does any unhandled message ([connection.py at v2.17.0](https://github.com/ronf/asyncssh/blob/v2.17.0/asyncssh/connection.py), `_recv_packet`).
  Messages above 49 before incoming encryption raise "Invalid request before key exchange was complete" (the 2.14.1 hardening, [commit 83e43f5](https://github.com/ronf/asyncssh/commit/83e43f5ea3470a8617fc388c72b062c7136efd7e)).
  A KEXINIT with `recv_seq != 0` raises "KEXINIT was not the first packet" (`_process_kexinit`).
  The window is tied to `_recv_encryption`, which is set when the client NEWKEYS arrives, so the Dropbear-style late window does not exist.

### Reports of incomplete strict KEX

Bäumer, Maehren, Brinkmann and Schwenk (CCS 2025) learned the handshake state machines of ten servers with strict KEX on, using a 94-symbol alphabet that includes optional, server-only and undefined messages ([CCS 2025, §3.2, Table 2](https://arxiv.org/pdf/2509.10895)).
Seven of the ten violate strict KEX (same, §4.2).
The tested versions and results that matter to us:

- OpenSSH 9.9p2: compliant (one of only two, with Go x/crypto/ssh) ([CCS 2025, §4.2](https://arxiv.org/pdf/2509.10895)).
- Dropbear 2025.87: category C4, "late message injection".
  Restrictions are lifted after the server sends NEWKEYS and before the client does, for message IDs below 50.
  Server replies in this window advance the encrypted send counter after the reset, which "directly violates the strict key exchange's goal to separate unencrypted and encrypted sequence numbers" ([CCS 2025, §4.1, §4.2](https://arxiv.org/pdf/2509.10895)).
  Our 2024.85 has the same code (above).
- AsyncSSH 2.20.0: only a minor C2 violation in DH group exchange (repeated `KEX_DH_GEX_REQUEST` is answered) ([CCS 2025, §4.2](https://arxiv.org/pdf/2509.10895)).
  It was hardened in 2.21.0 ([AsyncSSH changelog](https://github.com/ronf/asyncssh/blob/develop/docs/changes.rst), [commit 6ead910](https://github.com/ronf/asyncssh/commit/6ead9101fa24be459a11d3a3d7548847b1df44ed)).
  Our alphabet uses only curve25519, so this cannot be seen.
- Others, not our targets ([CCS 2025, §4.2-4.4](https://arxiv.org/pdf/2509.10895)):
  Erlang SSH (C3: IGNORE/DEBUG and connection-protocol messages accepted during the handshake, which led to CVE-2025-32433);
  Tectia 6.6.5 (C1 and C3, plus a rogue session attack, CVE-2025-32942);
  LANCOM LCOS (C3);
  libssh 0.11.1 (C2 in DHGEX);
  TinySSH (C4).
  Bitvise and libssh use a "taint" design: they note the violation and terminate at the end of the KEX instead of immediately, which the authors do not count as a violation in itself.
- Erlang's advisory for CVE-2025-46712 lists the accepted messages: after KEXINIT, DEBUG, IGNORE or UNIMPLEMENTED; after ECDH_INIT, DEBUG or UNIMPLEMENTED ([GHSA-934x-xq38-hhqf](https://github.com/erlang/otp/security/advisories/GHSA-934x-xq38-hhqf)).
- AsyncSSH 2.20.0 stopped sending `IGNORE` during a key exchange, because some peers fail on IGNORE during rekeying ([AsyncSSH changelog 2.20.0](https://github.com/ronf/asyncssh/blob/develop/docs/changes.rst), [commit b88eed6](https://github.com/ronf/asyncssh/commit/b88eed615a583eab77987bd213d15b1cc9a63a3a)).
  In 2.17.0, `send_packet` puts an `IGNORE` before **every** encrypted packet other than IGNORE and EXT_INFO ([connection.py at v2.17.0](https://github.com/ronf/asyncssh/blob/v2.17.0/asyncssh/connection.py)).
  So expect AsyncSSH outputs like `IGNORE+SERVICE_ACCEPT` and `IGNORE+UA_SUCCESS` [code].
- OpenSSH 10.4 (2026-07-06) disconnects on non-KEX messages during a post-authentication rekey.
  "Previously a malicious peer could continue sending non-key exchange messages without penalty. These would be buffered [...]" ([OpenSSH release notes, 10.4](https://www.openssh.com/releasenotes.html)).
  Our 9.2p1 predates this.

### AsyncSSH rogue extension negotiation and rogue session (CVE-2023-46445, CVE-2023-46446)

- Rogue extension negotiation (client side): the AsyncSSH client accepted an `EXT_INFO` injected in plaintext before the key exchange completed; prefix truncation then deletes the real one ([Terrapin, §6.1, Fig. 6](https://www.usenix.org/system/files/usenixsecurity24-baumer.pdf), [GHSA-cfc2-wr2v-gxm5](https://github.com/advisories/GHSA-cfc2-wr2v-gxm5)).
  It affects AsyncSSH < 2.14.1.
- Rogue session (server side): the AsyncSSH server accepted a `USERAUTH_REQUEST` injected before the client's NEWKEYS, and "defers it until the client has requested the authentication protocol" ([Terrapin, §6.2, Fig. 7](https://www.usenix.org/system/files/usenixsecurity24-baumer.pdf), [GHSA-c35q-ffpf-5qpm](https://github.com/advisories/GHSA-c35q-ffpf-5qpm)).
  It then "silently ignores any additional authentication request after a successful authentication" (Terrapin, §6.2).
  This affects AsyncSSH < 2.14.1.
- The 2.14.1 fix makes messages above 49 before incoming encryption, KEX messages outside a KEX, and auth messages outside authentication into protocol errors.
  It also adds `_auth_final`: after the first message above 79, further auth requests disconnect instead of being ignored ([commit 83e43f5](https://github.com/ronf/asyncssh/commit/83e43f5ea3470a8617fc388c72b062c7136efd7e)).

## 4. Other SSH server state-machine bugs (protocol behaviour only)

- **libssh CVE-2018-10933** (0.6 to before 0.7.6/0.8.4): a client that sends `SSH2_MSG_USERAUTH_SUCCESS` where the server expects `USERAUTH_REQUEST` gets the server's state machine set to authenticated, and can then create channels ([libssh advisory](https://www.libssh.org/security/advisories/CVE-2018-10933.txt)).
- **Paramiko CVE-2018-1000805**: the same class.
  The server dispatched a client-sent `MSG_USERAUTH_SUCCESS` to a handler meant for client use and marked the peer as authenticated ([paramiko#1283](https://github.com/paramiko/paramiko/issues/1283)).
- **Paramiko CVE-2018-7750**: the server did "not properly check whether authentication is completed before processing other requests, as demonstrated by channel-open" ([OSV](https://osv.dev/vulnerability/CVE-2018-7750)).
- **AsyncSSH CVE-2018-7749** (< 1.12.1): the same, "a customized SSH client can simply skip the authentication step" ([OSV](https://osv.dev/vulnerability/CVE-2018-7749)).
- **Erlang/OTP SSH CVE-2025-32433** (before OTP 27.3.3, 26.2.5.11, 25.3.2.20): `CHANNEL_OPEN` and `CHANNEL_REQUEST exec`, sent right after KEXINIT and before KEX_ECDH_INIT, are processed.
  After NEWKEYS and before any authentication, the server returns `CHANNEL_SUCCESS`, the command output, EOF, exit-status and CLOSE ([CCS 2025, §4.4, Fig. 7](https://arxiv.org/pdf/2509.10895), [GHSA-37cp-fgq5-7wc2](https://github.com/erlang/otp/security/advisories/GHSA-37cp-fgq5-7wc2)).
- **Tectia CVE-2025-32942**: Tectia buffers `USERAUTH_REQUEST` sent during the handshake and answers it after the handshake.
  It authenticates without a prior service request, and keeps answering service and auth requests after success, so `USERAUTH_SUCCESS` is sent more than once ([CCS 2025, §4.3, Fig. 6](https://arxiv.org/pdf/2509.10895)).
- **OpenSSH CVE-2025-26466** (9.5p1 to 9.9p1): a pre-auth memory/CPU DoS via `SSH2_MSG_PING` ([OpenSSH release notes, 9.9p2](https://www.openssh.com/releasenotes.html)).
  `PING` is not in our alphabet, and 9.2p1 predates PING (added in 9.5).
- **Dropbear GitHub #321** (regression from 2022.82, fixed in 2024.86): "failed assertion in common-channel.c:705: !channel->sent_close" on concurrent channel open/close ([Dropbear CHANGES](https://matt.ucc.asn.au/dropbear/CHANGES), [issue #321](https://github.com/mkj/dropbear/issues/321)).
  It is sporadic in the report, so in our models it would look like non-determinism around `CH_CLOSE` [infer].
- **AsyncSSH < 2.24.1**: shell/exec/subsystem requests could be sent more than once on a channel ([AsyncSSH changelog 2.24.1](https://github.com/ronf/asyncssh/blob/develop/docs/changes.rst)).

## 5. Summary table

`HS` = `KEXINIT KEX30 NEWKEYS`; `AUTH` = `HS SR_AUTH UA_PW_OK`.
"strict off" means learning with `SSHMapper(strict_kex=False)`.
Expected columns refer to OpenSSH 1:9.2p1-2+deb12u10 (O), Dropbear 2024.85 (D) and AsyncSSH 2.17.0 (A).

| # | Finding | Source | Affected implementation/version | Expressible? (input word) | Expected in our 3 targets? |
|---|---|---|---|---|---|
| 1 | Happy flow: server sends NEWKEYS with KEX31; security properties (no SR_AUTH accept without KEX, no channel without valid credentials) hold | [SPIN §5, §6.5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf); [Verleg §5](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf) | all tested | yes: `HS` → `NO_RESP, KEX31+NEWKEYS, NO_RESP`; catalogue `AUTH-WITHOUT-CREDENTIALS`, `UNAUTH-CHANNEL-OPEN` | yes, all three [lit for older versions]; a mismatch here points to a mapper problem first |
| 2 | Client KEXINIT not required: KEX proceeds without it | [Verleg §5.1](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf) | OpenSSH 6.9p1 | yes: `KEX30 KEX30 NEWKEYS SR_AUTH` | no [code]: O and D answer `KEX30` before KEXINIT with UNIMPLEMENTED, and a later KEXINIT fails the strict first-packet check; A disconnects ("Key exchange not in progress") |
| 3 | No rekey before authentication: KEXINIT → UNIMPL, NEWKEYS → disconnect | [SPIN §5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf); [NDSS'23 Table I](https://www.ndss-symposium.org/wp-content/uploads/2023-68-paper.pdf) | OpenSSH 6.9p1, 8.8p1 | yes: `HS SR_AUTH KEXINIT KEX30 NEWKEYS` (also without SR_AUTH) | O: yes [code: pre-auth dispatch in [auth2.c](https://github.com/openssh/openssh-portable/blob/V_9_2_P1/auth2.c) sends everything except SERVICE_REQUEST/USERAUTH_REQUEST to `dispatch_protocol_error` → UNIMPLEMENTED]; the result of the final NEWKEYS depends on our mapper's pending-key rule. D: no, rekey allowed [lit 2014.65]. A: unknown |
| 4 | Rekey after auth not state-preserving (UNIMPL becomes NO_RESP for SR_*/KEX30) | [SPIN §5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf); [Lenaerts §6.3](https://www.cs.ru.nl/bachelors-theses/2017/Toon_Lenaerts___4321219___Improving-protocol-state-fuzzing-of-SSH.pdf) | OpenSSH 6.6p1, 6.9p1 | yes: compare `AUTH SR_AUTH` with `AUTH KEXINIT KEX30 NEWKEYS SR_AUTH` | O: unknown. D, A: unknown (Dropbear preserved state in 2014.65 [lit]) |
| 5 | CH_CLOSE after a rekey closes the whole connection | [Verleg §5.3](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf) (not reproduced on 6.6p1 by [Lenaerts §5.2](https://www.cs.ru.nl/bachelors-theses/2017/Toon_Lenaerts___4321219___Improving-protocol-state-fuzzing-of-SSH.pdf)) | OpenSSH 6.9p1 | yes: `AUTH CH_OPEN KEXINIT KEX30 NEWKEYS CH_CLOSE` | unknown; not reported since 2016 |
| 6 | Auth request after UA_SUCCESS answered with UNIMPL instead of ignored (RFC 4252 §5.1 SHOULD) | [SPIN Table 5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf); [NDSS'23 Table I](https://www.ndss-symposium.org/wp-content/uploads/2023-68-paper.pdf) | OpenSSH 6.9p1, 8.8p1; Bitvise | yes: `AUTH UA_NONE`, `AUTH UA_PW_OK` | O: yes [code: post-auth dispatch in [serverloop.c](https://github.com/openssh/openssh-portable/blob/V_9_2_P1/serverloop.c) defaults to `dispatch_protocol_error` → UNIMPLEMENTED]. D: no, silently ignored when `authdone` [code [svr-auth.c](https://github.com/mkj/dropbear/blob/DROPBEAR_2024.85/src/svr-auth.c)]. A: `AUTH UA_NONE` → NO_RESP, but `AUTH CH_OPEN UA_NONE` → DISCONNECT (`_auth_final`) [code] |
| 7 | SR_AUTH outside the initial state answered with UNIMPL instead of accept/disconnect | [SPIN §6.4, Table 5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf); [NDSS'23 Table I](https://www.ndss-symposium.org/wp-content/uploads/2023-68-paper.pdf) | OpenSSH 6.9p1, 8.8p1; BitVise 8.49 | yes: `AUTH SR_AUTH` | O: yes [code: serverloop.c, as row 6]. D: no, SERVICE_ACCEPT at any time [code [svr-service.c](https://github.com/mkj/dropbear/blob/DROPBEAR_2024.85/src/svr-service.c)]. A: no, disconnects ("Unexpected service") [code] |
| 8 | SR_CONN before auth: disconnect | [Verleg Fig. 5.1](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf); [SPIN Fig. 6](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf) | OpenSSH 6.9p1 (conforming) | yes: `HS SR_CONN`, `HS SR_AUTH SR_CONN` | yes for all three [code: O `ssh_packet_disconnect("bad service request")`; D exits "Request for connection before auth"; A raises ServiceNotAvailable] |
| 9 | Channel open before auth gives UNIMPL in OpenSSH instead of the disconnect RFC 4252 §6 requires; no channel ever opens | [SPIN Fig. 6](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf) ("CH_\*, KEXINIT, KEX30 / UNIMPL" in pre-auth); [Lenaerts §5.1](https://www.cs.ru.nl/bachelors-theses/2017/Toon_Lenaerts___4321219___Improving-protocol-state-fuzzing-of-SSH.pdf) | OpenSSH 6.6p1, 6.9p1 | yes: `HS SR_AUTH CH_OPEN`; catalogue `CONN-BEFORE-AUTH` | O: yes, expect a CONN-BEFORE-AUTH hit with UNIMPLEMENTED (not a bypass) [code [dispatch.c](https://github.com/openssh/openssh-portable/blob/V_9_2_P1/dispatch.c)]. D: no, exits "before userauth" [code]. A: no, ProtocolError [code] |
| 10 | Authentication proceeds without SR_AUTH ("Missing SERVICE_REQUEST_USERAUTH") | [NDSS'23 §VIII-B](https://www.ndss-symposium.org/wp-content/uploads/2023-68-paper.pdf) | Dropbear 2020.81 (wontfix); Tectia 6.6.5 [CCS'25 §4.3](https://arxiv.org/pdf/2509.10895) | yes: `HS UA_PW_OK`, `HS UA_PW_NOK`; catalogue `UA-BEFORE-SR-AUTH` | D: yes [lit, design choice]. O: no, UNIMPLEMENTED (USERAUTH_REQUEST handler only registered after SR_AUTH) [code]. A: probably yes, `_process_userauth_request` has no service check [code, our own reading, not in the literature] |
| 11 | CH_CLOSE answered with CH_EOF instead of CH_CLOSE | [SPIN §6.5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf); [NDSS'23 §VIII-B](https://www.ndss-symposium.org/wp-content/uploads/2023-68-paper.pdf) | Dropbear 2014.65, 2020.81; fixed 2022.82 per NDSS'23 | yes: `AUTH CH_OPEN CH_CLOSE`; catalogue `CH-CLOSE-REPLY` | D: no [lit: fixed], though 2022.82-2024.85 carry the close/open regression of row 25. O, A: no [infer] |
| 12 | Second terminal request on one channel closes the connection | [SPIN §5](https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf); [Verleg §5.3](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf) | OpenSSH 6.9p1, Dropbear 2014.65 | partly: we have exec, not pty: `AUTH CH_OPEN CH_REQUEST_EXEC CH_REQUEST_EXEC`; `exec true` may already have closed the channel (then `NO_CHANNEL`) | unknown for O, D. A: likely accepted, since < 2.24.1 allowed repeated exec [lit changelog] |
| 13 | Data after CH_EOF closes the connection; no replies after EOF | [Verleg Fig. 5.12](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf) | Dropbear 2014.65 | yes: `AUTH CH_OPEN CH_EOF CH_DATA` | unknown |
| 14 | During post-auth rekey, after server NEWKEYS and before client NEWKEYS, upper-layer messages are processed under old keys; CH_CLOSE reply delayed until client NEWKEYS | [NDSS'23 §VIII-B](https://www.ndss-symposium.org/wp-content/uploads/2023-68-paper.pdf) | OpenSSH 8.8p1, BitVise 8.49 | yes: `AUTH KEXINIT KEX30 CH_OPEN CH_CLOSE NEWKEYS` | O: likely yes [infer: 9.2 predates the 10.4 change]. D: no, `requirenext=NEWKEYS` makes message 90 exit [code]. A: unknown |
| 15 | Non-KEX messages during post-auth rekey buffered rather than rejected; replies released after the rekey (Verleg's "buffering", which multiplies states) | [OpenSSH 10.4 notes](https://www.openssh.com/releasenotes.html); [Verleg §4.4.3, §5.1](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf); [CCS'25 §4](https://arxiv.org/pdf/2509.10895) (Bitvise) | OpenSSH < 10.4; Bitvise; Tectia; PowerShell | yes: `AUTH KEXINIT CH_OPEN KEX30 NEWKEYS` and `HS SR_AUTH KEXINIT SR_AUTH KEX30 NEWKEYS` | O: likely yes for post-auth [lit notes]. D: no, exits on non-KEX during KEX [code; lit 2014.65]. A: likely yes; 2.17.0 defers outgoing SERVICE_ACCEPT and messages > 49 while `_kex_complete` is false [code]. Watch for a growing output alphabet |
| 16 | Unresponsive state after `KEXINIT NEWKEYS`; rekey messages accepted in any order | [Verleg Figs. 5.4, 5.6](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf) | Bitvise 6.45, Tectia 6.4.12 | yes: `KEXINIT NEWKEYS`; `HS SR_AUTH KEXINIT NEWKEYS KEX30` | no: with strict KEX all three must terminate on an out-of-sequence NEWKEYS (`STRICT-KEX-REPEATED-MSG`) [code: O `kex_protocol_error`, D `requirenext`, A "New keys not negotiated"] |
| 17 | Terrapin precondition: IGNORE/DEBUG/UNIMPLEMENTED tolerated during the initial KEX (RcvIncrease) | [Terrapin §4.1](https://www.usenix.org/system/files/usenixsecurity24-baumer.pdf) | every non-strict implementation (e.g. OpenSSH ≤ 9.5p1, AsyncSSH ≤ 2.14.1, Dropbear ≤ 2022.83) | yes: `KEXINIT IGNORE KEX30 NEWKEYS SR_AUTH` (also DEBUG, UNIMPLEMENTED, and after KEX30) | strict on: no, DISCONNECT/CLOSED at the injected message for O and A; D: see row 19. Strict off: yes for all three (RFC 4253 §11.2 behaviour); a good control |
| 18 | Unknown/unexpected message during KEX answered with UNIMPLEMENTED (SndIncrease); Dropbear disconnects instead | [Terrapin §4.1](https://www.usenix.org/system/files/usenixsecurity24-baumer.pdf) | Dropbear 2022.83 disconnects; others reply | partly: no unknown-ID input; nearest is a known message out of place, strict off: `KEXINIT KEXINIT`, `KEXINIT SR_AUTH`, `KEXINIT KEX30 KEX30` | strict off: O UNIMPLEMENTED for unexpected 1-49 (`kex_protocol_error`) [code]; D UNIMPLEMENTED for 1-49 except SR/SA/KEXINIT, which exit [code]; A ProtocolError for SR, KEXINIT-in-KEX [code]. Strict on: all terminate, except row 19 |
| 19 | Strict KEX C4, late injection: restrictions lifted after the server's own NEWKEYS, before the client's; replies there shift the encrypted send sequence | [CCS'25 §4.2](https://arxiv.org/pdf/2509.10895); [Dropbear 2025.88](https://matt.ucc.asn.au/dropbear/CHANGES); [commit 6b0e004](https://github.com/mkj/dropbear/commit/6b0e0041bc5cc8adca0e1ff1823821935e843dbc) | Dropbear ≤ 2025.87; TinySSH 20250201 | yes: `KEXINIT KEX30 IGNORE NEWKEYS SR_AUTH` (and DEBUG, UNIMPLEMENTED); `KEXINIT KEX30 KEX30 NEWKEYS SR_AUTH` (server answers UNIMPLEMENTED, encrypted) | D: **yes**; 2024.85 has the pre-fix check and Alpine 3.20 has no backport [code + lit]. O: no [lit: 9.9p2 compliant; same `KEX_INITIAL` logic in the backport, code]. A: no, window tied to `_recv_encryption` [code] |
| 20 | Strict KEX C1, first packet must be KEXINIT (retrospective check) | [OpenSSH PROTOCOL §1.9](https://raw.githubusercontent.com/openssh/openssh-portable/V_9_6_P1/PROTOCOL); [CCS'25 §4.1-4.2](https://arxiv.org/pdf/2509.10895) | Tectia 6.6.5 violates | yes: `IGNORE KEXINIT`, `DEBUG KEXINIT`, `UNIMPLEMENTED KEXINIT`; catalogue `STRICT-KEX-FIRST-KEXINIT` | no violation expected: `NO_RESP` then DISCONNECT/CLOSED on KEXINIT for all three [code] |
| 21 | Strict KEX C3, partial hardening: optional or connection messages tolerated during KEX | [CCS'25 §4.2](https://arxiv.org/pdf/2509.10895); [GHSA-934x-xq38-hhqf](https://github.com/erlang/otp/security/advisories/GHSA-934x-xq38-hhqf) | Erlang (CVE-2025-46712), Tectia, LANCOM LCOS | yes: `KEXINIT DEBUG`, `KEXINIT UNIMPLEMENTED`, `KEXINIT KEX30 DEBUG`(*), `KEXINIT CH_OPEN`; catalogue `STRICT-KEX-NON-KEX-MSG` | no for O [lit] and A [code]; D: no before its own NEWKEYS [code], (*) yes after it (row 19) |
| 22 | Strict KEX C2, flow-dependent: repeated `KEX_DH_GEX_REQUEST` answered | [CCS'25 §4.2](https://arxiv.org/pdf/2509.10895) | AsyncSSH 2.20.0; libssh 0.11.1 (DHGEX) | no: the alphabet is curve25519 only | n/a |
| 23 | Rogue session: USERAUTH_REQUEST injected before client NEWKEYS is accepted and deferred until SR_AUTH; extra auth requests silently ignored | [Terrapin §6.2](https://www.usenix.org/system/files/usenixsecurity24-baumer.pdf); [GHSA-c35q-ffpf-5qpm](https://github.com/advisories/GHSA-c35q-ffpf-5qpm); Tectia variant [CCS'25 §4.3](https://arxiv.org/pdf/2509.10895) | AsyncSSH < 2.14.1 (CVE-2023-46446); Tectia 6.6.5 (CVE-2025-32942) | yes: `KEXINIT KEX30 UA_PW_OK NEWKEYS SR_AUTH` (run with strict off too, so strict KEX does not mask the state-machine fix) | no for all three: O has no handler for messages > 49 during the initial KEX and disconnects with "protocol error" ([dispatch.c](https://github.com/openssh/openssh-portable/blob/V_9_2_P1/dispatch.c)), with or without strict KEX [code]; D exits (message 50 while `requirenext`) [code]; A "Invalid request before key exchange was complete" since 2.14.1 [code + lit] |
| 24 | Rogue extension negotiation: unauthenticated EXT_INFO accepted by the client | [Terrapin §6.1](https://www.usenix.org/system/files/usenixsecurity24-baumer.pdf); [GHSA-cfc2-wr2v-gxm5](https://github.com/advisories/GHSA-cfc2-wr2v-gxm5) | AsyncSSH client < 2.14.1 (CVE-2023-46445) | no: client-side, and EXT_INFO is not an input | n/a |
| 25 | Assertion failure on concurrent channel open/close | [Dropbear CHANGES 2024.86](https://matt.ucc.asn.au/dropbear/CHANGES); [issue #321](https://github.com/mkj/dropbear/issues/321) | Dropbear 2022.82-2024.85 | maybe: `AUTH CH_OPEN CH_REQUEST_EXEC CH_CLOSE CH_OPEN`, timing-dependent | D: unknown; may show up as non-determinism or `CLOSED`. O, A: n/a |
| 26 | Client-sent USERAUTH_SUCCESS sets server to authenticated | [libssh advisory](https://www.libssh.org/security/advisories/CVE-2018-10933.txt); [paramiko#1283](https://github.com/paramiko/paramiko/issues/1283) | libssh 0.6-0.7.5/0.8.3 (CVE-2018-10933); Paramiko (CVE-2018-1000805) | no: needs a new input, client-sent message 52 | unknown; worth an extra input symbol |
| 27 | Requests (e.g. channel open) processed before authentication completes | [OSV CVE-2018-7749](https://osv.dev/vulnerability/CVE-2018-7749); [OSV CVE-2018-7750](https://osv.dev/vulnerability/CVE-2018-7750) | AsyncSSH < 1.12.1; Paramiko < 2.4.1 etc. | yes: `HS SR_AUTH CH_OPEN`, `HS SR_AUTH UA_PW_NOK CH_OPEN CH_REQUEST_EXEC`; catalogue `UNAUTH-CHANNEL-OPEN` | no for all three [code]; O replies UNIMPLEMENTED (row 9), D and A disconnect |
| 28 | Connection-protocol messages during the handshake processed, then answered before auth (pre-auth RCE) | [CCS'25 §4.4](https://arxiv.org/pdf/2509.10895); [GHSA-37cp-fgq5-7wc2](https://github.com/erlang/otp/security/advisories/GHSA-37cp-fgq5-7wc2) | Erlang/OTP SSH before 27.3.3 / 26.2.5.11 / 25.3.2.20 (CVE-2025-32433) | partly: `KEXINIT CH_OPEN KEX30 NEWKEYS SR_AUTH` (would show `CH_OPEN_SUCCESS` before UA_SUCCESS); the exec part needs the server channel id, so `CH_REQUEST_EXEC` gives `NO_CHANNEL` | no for all three [code: O disconnects with "protocol error" on messages > 49 during the initial KEX; D exits on message > 49 during KEX; A rejects > 49 before incoming encryption] |
| 29 | AsyncSSH emits IGNORE before every encrypted packet | [commit b88eed6](https://github.com/ronf/asyncssh/commit/b88eed615a583eab77987bd213d15b1cc9a63a3a); [connection.py v2.17.0](https://github.com/ronf/asyncssh/blob/v2.17.0/asyncssh/connection.py) | AsyncSSH ≤ 2.19.x | yes: any post-NEWKEYS output, e.g. `HS SR_AUTH` → `IGNORE+SERVICE_ACCEPT` | A: yes [code]; this is an output-abstraction effect, not a bug |
| 30 | OpenSSH sends GLOBAL_REQUEST `hostkeys-00@openssh.com` after auth | [Verleg §5.2](https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf) | OpenSSH 6.9p1 | yes: `AUTH` → `UA_SUCCESS+GLOBAL_REQUEST` | O: yes [infer]; sanity check for the output side |

## 6. Caveats

- [code] entries come from reading the exact tagged sources linked above, not from running anything.
  They are predictions for the models to confirm or refute.
- Row 10 for AsyncSSH and rows 14-15 for AsyncSSH are our own inferences with no published report.
  If a model confirms them, treat them as candidate findings under the repository safety rule (CLAUDE.md) until checked with the maintainers.
- The literature's OpenSSH results come from 6.6p1, 6.9p1, 8.8p1 (non-strict) and 9.9p2 (strict, handshake only).
  Nothing has been published on Debian's 9.2p1 backport or on AsyncSSH 2.17.0 specifically.
- The CCS 2025 authors note that what a mapper assumes about an out-of-order NEWKEYS (switch keys or not, reset sequence numbers or not) creates mapper-specific extra states.
  So state counts are only comparable between mappers that make the same assumptions ([CCS 2025, §6.4](https://arxiv.org/pdf/2509.10895)).
  Our rule ("switch only if pending keys exist") is in the [mapper spec](../docs/MAPPER-SPEC-SSH.md).
- OpenSSH's `LoginGraceTime` closes unauthenticated connections on a timer, a known source of cache conflicts in learning ([CCS 2025, §6.4](https://arxiv.org/pdf/2509.10895)).
