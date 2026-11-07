# Literature notes: state-machine learning of SSH servers

Compiled 2026-11-07 for the study that learns Mealy models of OpenSSH, Dropbear and Go x/crypto/ssh servers with AALpy through a mapper over RFC 4253 transport and RFC 4252 auth messages, then diffs the models.
Everything below was read from the primary source (PDF or RFC text) unless marked "unverified".
Where a number or claim comes from memory rather than a fetched source, it is marked "unverified".

## 0. Sources read

| Short name | Reference | URL / DOI |
|---|---|---|
| dRP15 | J. de Ruiter, E. Poll. Protocol State Fuzzing of TLS Implementations. USENIX Security 2015, pp. 193-206. | https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/de-ruiter (PDF: https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-de-ruiter.pdf) |
| Verleg16 | P. Verleg. Inferring SSH state machines using protocol state fuzzing. MSc thesis, Radboud University, 10 Feb 2016. | https://cs.ru.nl/masters-theses/2016/P_Verleg___Inferring_SSH_state_machines_using_protocol_state_fuzzing.pdf |
| Lenaerts17 | T. Lenaerts. Improving Protocol State Fuzzing of SSH. BSc thesis, Radboud University, 23 Jan 2017. | https://www.cs.ru.nl/bachelors-theses/2017/Toon_Lenaerts___4321219___Improving-protocol-state-fuzzing-of-SSH.pdf |
| FLPdRVV17 | P. Fiterau-Brostean, T. Lenaerts, E. Poll, J. de Ruiter, F. Vaandrager, P. Verleg. Model Learning and Model Checking of SSH Implementations. SPIN 2017 (24th ACM SIGSOFT Int. SPIN Symposium), pp. 142-151. | DOI 10.1145/3092282.3092289; https://www.cs.ru.nl/~erikpoll/papers/spin2017.pdf; models and properties: https://gitlab.science.ru.nl/pfiteraubrostean/Learning-SSH-Paper ; benchmark page https://automata.cs.ru.nl/BenchmarkSSH-Fiterau-BrosteanEtAl2017 |
| FJST23 | P. Fiterau-Brostean, B. Jonsson, K. Sagonas, F. Taaquist. Automata-Based Automated Detection of State Machine Bugs in Protocol Implementations. NDSS 2023. | https://www.ndss-symposium.org/ndss-paper/automata-based-automated-detection-of-state-machine-bugs-in-protocol-implementations ; PDF https://www.ndss-symposium.org/wp-content/uploads/2023-68-paper.pdf ; artifact https://zenodo.org/record/7129240 |
| FJMdRSS20 | P. Fiterau-Brostean, B. Jonsson, R. Merget, J. de Ruiter, K. Sagonas, J. Somorovsky. Analysis of DTLS Implementations Using Protocol State Fuzzing. USENIX Security 2020, pp. 2523-2540. | https://usenix.org/conference/usenixsecurity20/presentation/fiterau-brostean |
| BBS24 | F. Baeumer, M. Brinkmann, J. Schwenk. Terrapin Attack: Breaking SSH Channel Integrity By Sequence Number Manipulation. USENIX Security 2024. | https://terrapin-attack.com/ ; arXiv 2312.12422 ; CVE-2023-48795 |
| BMBS25 | F. Baeumer, M. Maehren, M. Brinkmann, J. Schwenk. Finding SSH Strict Key Exchange Violations by State Learning. ACM CCS 2025. | DOI 10.1145/3719027.3765208 ; arXiv 2509.10895 |
| strict-kex | D. Miller. SSH Strict KEX extension. IETF Internet-Draft draft-ietf-sshm-strict-kex (-02 read; earlier name draft-miller-sshm-strict-kex). | https://datatracker.ietf.org/doc/draft-ietf-sshm-strict-kex/ |
| RFCs | RFC 4251, 4252, 4253, 4254 (Jan 2006), RFC 8308 (Mar 2018). | https://www.rfc-editor.org/rfc/rfcNNNN |

## 1. de Ruiter and Poll, "Protocol State Fuzzing of TLS Implementations" (USENIX Security 2015)

**What was learned.**
Nine TLS implementations (Table 1 of the paper), server side for all of them and client side for several:
GnuTLS 3.3.8 and 3.3.12, Java Secure Socket Extension (JSSE) 1.8.0_25 and 1.8.0_31, mbed TLS (PolarSSL) 1.3.10, miTLS 0.1.3, RSA BSAFE for C 4.0.4, RSA BSAFE for Java 6.1.1, NSS 3.17.4, OpenSSL 1.0.1g, 1.0.1j, 1.0.1l and 1.0.2, nqsb-TLS 0.4.0.
Demo server/client programs shipped with each library were used (a small wrapper for JSSE).

**Learning setup.**
- LearnLib (L*-style Mealy learner), black-box only.
- Equivalence queries approximated by Chow's W-method, with a LearnLib "depth": the upper bound on state count is states-in-hypothesis plus depth (depth 2 for the server results).
- Their modification: do not extend test traces that already ended in a closed connection, because everything after "Connection closed" is the same output.
  On GnuTLS 3.3.12 this cut the number of equivalence queries by more than a factor of 15 against the unmodified W-method.
- Input alphabet (server tests): ClientHello (RSA and DHE), Certificate (RSA and empty), ClientKeyExchange, ClientCertificateVerify, ChangeCipherSpec, Finished, ApplicationData (regular and empty), HeartbeatRequest, HeartbeatResponse.
  The per-run alphabet was smaller: ClientHello(RSA), Certificate(empty), ClientKeyExchange, ChangeCipherSpec, Finished, ApplicationData (regular and empty), HeartbeatRequest.
- A test harness (the "mapper") is a stateless TLS implementation that holds key-exchange values, keys, and whether ChangeCipherSpec was sent or received (to decide when to encrypt and MAC).
  On reset it sets its variables from a fresh ClientHello exchange to avoid null-pointer failures when messages arrive out of order.
- Timing: the harness waits a fixed, per-implementation timeout (100 ms to 1500 ms, Table 2) for output.
  miTLS looked non-deterministic until the timeout was raised, because late responses showed up as replies to the next input.
- Total learning time per server ranged from about 6 to 9 minutes up to 8 h 16 min (OpenSSL 1.0.2 was the 8 h case).

**Output abstraction.**
All TLS handshake and alert messages, plus four harness symbols: `Empty` (timeout, no data), `Decryption failed`, `Connection closed`, and (implicitly) alert descriptions.
Alert reasons are kept, which is why different alert texts produce different transitions.

**Findings (3 of 9 implementations had new security flaws).**
- GnuTLS 3.3.8: a HeartbeatRequest during the handshake resets the handshake-hash buffer, so a client that does the same completes a handshake with no integrity on earlier handshake messages (downgrade possible). Fixed in 3.3.9; the 3.3.12 model has no shadow path.
- JSSE 1.8.0_25: a ChangeCipherSpec can be omitted, the server still answers a plaintext Finished and then accepts plaintext application data; CVE-2014-6593, fixed January 2015 (confirmed on 1.8.0_31). Found in parallel by Beurdouche et al. (SMACK).
- OpenSSL 1.0.1g: early ChangeCipherSpec yields keys from an empty master secret (known bug, rediscovered).
  OpenSSL 1.0.1j: a premature extra ChangeCipherSpec makes server and client keys equal and resets the cipher state; reported and fixed in 1.0.1k.
- Non-security anomalies: nqsb-TLS 0.4.0 left alerts unencrypted after ChangeCipherSpec (fixed) and answers ChangeCipherSpec immediately instead of waiting for Finished; NSS 3.17.4 hangs (no close) on non-handshake data before ClientHello; BSAFE for C used inconsistent alerts ("Bad record MAC" where "Unexpected message" is expected); mbed TLS accepted empty ApplicationData in odd orders.
- All learned server models differ, so models fingerprint implementations.

**How a model difference was judged to be a real bug.**
Entirely manual:
1. Count the paths that lead to application-data exchange; any extra path (marked red in their figures) is a flaw.
2. Look for more states than the specification needs, and for unexpected or superfluous transitions, especially unusual alerts ("Bad record MAC", "Decryption failed").
3. For anything odd, inspect the source and craft a modified harness to try to exploit it (e.g. reset the harness hash buffer on the client side too).
4. Report to vendors, check whether the model of the fixed version removes the shadow states (GnuTLS 3.3.9+, OpenSSL 1.0.1k+, JSSE Jan 2015 update).
The paper's stated position: any spurious state in a security protocol implementation is suspect, even if no exploit is found.
Limits they state: deliberate backdoors (e.g. triggered after 100 messages) and message-parsing bugs are out of reach.

## 2. SSH: Verleg (2016), Lenaerts (2017) and Fiterau-Brostean et al. (SPIN 2017)

### 2.1 Lineage

- Verleg16 (MSc): six servers, three separate models per server (transport, user-auth, connection), random-walk equivalence oracle, manual analysis against a security definition per layer.
- Lenaerts17 (BSc): repeats OpenSSH 6.6p1 as one combined model with the Smeenk et al. adaptive-distinguishing-sequence tester (Yannakakis-Lee based), NuSMV for two of Verleg's three properties.
- FLPdRVV17 (SPIN): three servers, one combined model each, full LTL property set (11 properties), NuSMV.
- Tijssen (2013 BSc) and Boss (2012 BSc) are earlier SSH model-based testing / learning work (cited, not read).

### 2.2 Implementations and versions

| Work | Implementations |
|---|---|
| Verleg16 | OpenSSH 6.9p1-2, DropBear 2014.65-1, Bitvise 6.45, PowerShell (N Software) 6.0.5732, Tectia 6.4.12.353, CiscoSSH 1.25 (Catalyst 3550). |
| Lenaerts17 | OpenSSH 6.6p1 only. |
| SPIN 2017 (Table 4) | OpenSSH 6.9p1-2, Bitvise 7.23, DropBear v2014.65. |
| FJST23 (re-test) | Bitvise 8.49, Dropbear v2020.81, OpenSSH 8.8p1. |
| BMBS25 (strict KEX) | OpenSSH 9.9p2, Dropbear 2025.87, Go x/crypto/ssh 0.37.0, plus AsyncSSH 2.20.0, Bitvise 9.43, Erlang SSH 5.2.8, LANCOM LCOS, libssh 0.11.1, Tectia 6.6.5.353, TinySSH 20250201. |

### 2.3 Input alphabet (SPIN 2017, Tables 1-3; `*` = in the restricted alphabet)

The principle: only messages a client sends to a server ("outgoing only"), only terminal-service messages from the connection layer, start after the TCP connection and version-string exchange, no algorithm exploration (defaults only).

| Layer | Inputs |
|---|---|
| Transport (9) | `KEXINIT*` (with `first_kex_packet_follows` = false), `KEX30*`, `NEWKEYS*`, `SR_AUTH*` (service request ssh-userauth), `SR_CONN*` (service request ssh-connection), `DISCONNECT`, `IGNORE`, `UNIMPL`, `DEBUG` |
| User auth (5) | `UA_NONE`, `UA_PK_OK*`, `UA_PK_NOK*`, `UA_PW_OK`, `UA_PW_NOK` (valid and invalid credentials; host-based not supported) |
| Connection (7) | `CH_OPEN*`, `CH_CLOSE*`, `CH_EOF*`, `CH_DATA*`, `CH_EDATA`, `CH_WINDOW_ADJUST`, `CH_REQUEST_PTY*` |

- Full alphabet: 21 symbols (used for OpenSSH).
  Restricted alphabet: 12 symbols (5 transport, 2 auth, 5 connection), used for Bitvise and DropBear because learning took days.
  Excluded from the restricted set: `DISCONNECT` (slow), `IGNORE`, `UNIMPL`, `DEBUG` (OpenSSH showed they never change state), password auth (the servers take 2-3 s to answer a password attempt, public-key attempts are fast), `CH_EDATA`, `CH_WINDOW_ADJUST`.
- Excluded as never-client-sent: `SERVICE_ACCEPT`, `UA_ACCEPT`, `UA_FAILURE`, `UA_BANNER`, `UA_PK_OK` server variant, `UA_PW_CHANGEREQ`, `CH_SUCCESS`, `CH_FAILURE`.
- Verleg's transport alphabet additionally had `GUESSINIT` (KEXINIT with `first_kex_packet_follows` = true; correct guesses only, servers' cipher preferences were edited so the guess is right) and a composite `REKEY` input (kexinit, kex30, newkeys in one input) for the upper layers.
  Lenaerts found that the atomic REKEY shorthand hid bugs: a counterexample appeared only after he used the three steps separately.

### 2.4 Output abstraction

- Outputs are SSH message names: `KEXINIT`, `KEX31`, `NEWKEYS`, `SR_ACCEPT`, `UA_SUCCESS`, `UA_FAILURE`, `CH_OPEN_SUCCESS`, `CH_SUCCESS`, `CH_CLOSE`, `CH_EOF`, `UNIMPL`, `DEBUG`, `IGNORE`, `DISCONNECT`, plus special symbols `NO_RESP` (timeout), `NO_CONN`, `CH_NONE`, `CH_MAX`, `BUFFERED`.
- Several messages answering one input are concatenated into one output (e.g. `KEX31+NEWKEYS`, Tectia `IGNORE+UA_BANNER+UA_SUCCESS`); everything that arrives within the timeout is part of the same output.
- `IGNORE` and `DEBUG` that servers add on their own (Tectia, Bitvise) were filtered out of outputs in Verleg's setup.
- `BUFFERED`: when a server queues higher-layer requests during rekeying and answers them after the new keys, the whole run of queued responses is collapsed to one symbol.
  Without this the learner would not terminate (one distinct output per buffered sequence).

### 2.5 Mapper and crypto state

- Built by gutting Paramiko's control logic (Python) and driving its packet encryption, decryption and constructors from the learner's socket.
  The mapper "is a client with the control logic replaced".
- State variables: server's KEXINIT preferences (defaults to the RFC-mandatory algorithms if no KEXINIT was received), DH parameters, exchange hash and session id, pending keys, the sequence number of the last received message (for crafting `UNIMPL`), the buffer of open channels.
- Keys: saved on `KEX31`; sender-side keys are installed after the mapper sends `NEWKEYS`, receiver-side keys after it receives `NEWKEYS` (FJST23 describes this explicitly).
- Channel buffer limited to one open channel, enforced inside the mapper: a second `CH_OPEN` is answered by the mapper with `CH_MAX`, any channel input with no open channel with `CH_NONE`, anything after the connection is lost with `NO_CONN`, without contacting the server.
  This bounds the state space but adds many mapper-induced states and means "two channels at once" was never tested.
- Usernames: mapper uses identical usernames across requests, because OpenSSH and Tectia refuse a username change and the learner otherwise inferred wrong models (found with OpenSSH's debug log).
- Not modelled: parameters (session id, algorithm choices, sequence numbers), timing behaviour, mapper was not formalised so no concretisation of models; model-checking counterexamples must be re-checked as real mapper runs.

### 2.6 Non-determinism, timing, caching (what they hit and how they fixed it)

- Sources named by Verleg and SPIN:
  1. Underspecification and legal asynchrony (free interleaving, `IGNORE`/`DEBUG` insertion at any time).
  2. Timeouts: mapper gives up before the server answers, or late output is attributed to the next input.
  3. Servers that misbehave if the next input arrives too soon: on DropBear a valid auth within about 5 ms after the auth request can fail wrongly.
- Fixes:
  - Per-implementation, and in Verleg per-query-type, timeouts and inter-input delays, tuned by hand ("trial and error").
    Slow query types such as authentication get longer timeouts.
  - An SQLite log of every (trace, response) pair; each new observation is checked against earlier ones and an exception is raised on a conflict, which was then investigated manually until a timing setting made behaviour deterministic.
  - The same cache answers repeated queries without touching the server and lets a crashed or multi-day run resume (Lenaerts repaired Verleg's resume implementation).
  - Debug mode where the mapper accepts a whole trace (`20 kexinit kex30 newkeys reset` repeats a rekey 20 times to spot variance).
  - Lenaerts notes he did not implement "re-run on conflict and take the second answer"; he only suggests it.
  - Query localhost where possible (less timing noise); Bitvise ran in a VM on the Windows host.
- Cost: with 0.5 s per input and about 10 inputs per query, 40000 queries are roughly 55 hours.
  Runs spanned several days and the lack of parallelism was called out as a limitation.

### 2.7 Equivalence oracle, queries and learning time (SPIN Table 4)

| SUT | States | Hypotheses | Membership queries | Test queries (last hypothesis) | Alphabet |
|---|---|---|---|---|---|
| OpenSSH 6.9p1-2 | 31 | 4 | 19 836 | 76 418 | full (21) |
| Bitvise 7.23 | 65 | 15 | 24 996 | 58 423 | restricted (12) |
| DropBear v2014.65 | 29 | 8 | 8 357 | 64 478 | restricted (12) |

- LearnLib; test method of Smeenk et al. 2015 (ICFEM, adaptive distinguishing sequences, Lee-Yannakakis).
  Tests = access sequence + middle section of length k + distinguishing sequence.
  Random variant: k = 4, 40 000 tests (OpenSSH) or 20 000 tests (Bitvise, DropBear).
  Then exhaustive with k = 2 for all three, which gives the guarantee "correct unless the real machine has at least k more states than the hypothesis".
- Lenaerts (OpenSSH 6.6p1, combined model): 26 states, 619 transitions, 2 hypotheses, exhaustive k = 2 took 32 728 tests; k = 3 would take 353 835 and k = 4 about 7.3 million.
  A rekey counterexample was found days before the deadline (rekey from `authed`, `has channel`, `has pty` led to different states), so even k = 2 exhaustive was not enough.
- State blow-up reasons: buffering during rekey (Bitvise), rekey states duplicating every state where rekey is allowed, and mapper-induced `CH_NONE`/`CH_MAX` states.
- FJST23 re-learning: models after two days; only Dropbear v2020.81 converged.

### 2.8 Properties model-checked (NuSMV, LTL with past operators), derived from the RFCs

Properties 1-2 characterise the mapper; the rest follow.

| # | Class | Content | RFC | Key word |
|---|---|---|---|---|
| 1-2 | basic | After `NO_CONN` only `NO_CONN`/`CH_MAX`/`CH_NONE`; channel buffer semantics of the mapper | n/a | n/a |
| 3 | security (transport) | `SR_ACCEPT` for `ssh-userauth` only if KEXINIT, KEX30, NEWKEYS were all done earlier | 4253 | n/a |
| 4 | security (auth) | A channel can be opened only if no `UA_FAILURE` since the last `UA_SUCCESS` | 4252 | n/a |
| 5 | rekey | After a successful service request and before auth (and again after auth) KEXINIT, KEX30, NEWKEYS in sequence must succeed | 4253 s9 | "preferably in all states" |
| rekey-2 | rekey | State after a successful rekey is equivalent to the state before (checked by script, not LTL) | 4253 s9 | n/a |
| 6 | functional | After `DISCONNECT` no output except mapper outputs | 4253 s11.1 | MUST |
| 7 | functional | After sending KEXINIT, no further KEXINIT or `SR_ACCEPT` until NEWKEYS sent | 4253 s7.1 | MUST |
| 8 | functional | Service request answered by `SR_ACCEPT`, `DISCONNECT` or `NO_CONN` (not in initial state) | 4253 s10 | MUST / SHOULD |
| 9 | functional | Rejected auth request gets `UA_FAILURE` | 4252 s5.1 | MUST |
| 10 | functional | `UA_SUCCESS` at most once | 4252 s5.1 | MUST |
| 11 | functional | Auth requests after `UA_SUCCESS` get no response | 4252 s5.1, s5.3 | SHOULD |
| 12 | functional | `CH_CLOSE` is answered by `CH_CLOSE` | 4254 s5.3 | MUST |

FJST23 re-expressed the 11 functional/security LTL properties as DFA bug patterns and added five (Auth Fail After Rekey, Channel Open Fail After Rekey, Channel Request Terminal Fail After Rekey, Missing NEWKEYS, Missing SERVICE_REQUEST_USERAUTH).
Properties are checked on the mapper-induced abstraction, not on the concrete server.

### 2.9 Concrete deviations found, by implementation (the list to re-check)

SPIN 2017 headline: all models satisfy the security properties (3 and 4); several RFC violations.
Table 5 of SPIN (confirmed from the rendered figure; red = violated; `*` = violated only because the server answers `UNIMPL` instead of the RFC-suggested output):

| Property | OpenSSH 6.9p1 | Bitvise 7.23 | DropBear 2014.65 |
|---|---|---|---|
| 3, 4 (security) | holds | holds | holds |
| 5 rekey before auth | **violated** | holds | holds |
| 5 rekey after auth | holds | **violated** (buffering; checked with `validAuthReq` instead of `UA_SUCCESS`) | holds |
| 6, 7, 9, 10 | holds | holds | holds |
| 8 service request response | violated* | violated | holds |
| 11 auth after success silently ignored (SHOULD) | violated* | violated* | holds |
| 12 `CH_CLOSE` answered by `CH_CLOSE` | holds | holds | **violated** |

Checklist, with the source of each item (V = Verleg16, L = Lenaerts17, S = SPIN17, N = FJST23).
Status column is for us to fill in on current versions.

OpenSSH:

1. Rekey is refused before authentication: KEXINIT in the pre-auth (service-accepted) state is answered `UNIMPL`; after the first rekey `SR_*`/`KEX30` answers change from `UNIMPL` to `NO_RESP` and NEWKEYS then disconnects (V, S, N "Rekey Fail Before Auth"). Re-check on current OpenSSH.
2. Very liberal key exchange start: no KEXINIT from the client is needed; any of `SR_*`, `KEX30`, `UNIMPL`, `DEBUG`, `IGNORE`, `KEXINIT` in the initial state is answered with the server's KEXINIT and the server guesses the parameters (V: OpenSSH 6.9; S Figure 6). This was never confirmed against RFC 4253 s7.1 by the developers (no reply to Verleg).
   Likely changed by strict KEX (BMBS25 says OpenSSH 9.9p2 is compliant, i.e. a non-KEXINIT first packet closes the connection when strict KEX is negotiated). Re-check without strict KEX too.
3. Pre-auth `SR_CONN` produces `DISCONNECT`; `NEWKEYS` in the `keyed` state is `NO_CONN` (V Fig 5.1, S Fig 6).
4. Unexpected authentication requests after `UA_SUCCESS` get `UNIMPL`, not silence (S property 11; N "Unignored Auth Request After USERAUTH_SUCCESS", still present in 8.8p1).
5. Service request answered with something other than `SR_ACCEPT`/`DISCONNECT` (S property 8); N lists "Invalid SERVICE_REQUEST_USERAUTH Response" for OpenSSH 8.8p1 and Bitvise 8.49 (details in the NDSS appendix, not extracted).
6. Username change between auth requests is refused (also Tectia); RFC 4252 s5 says the username "MAY change" and the server must flush state or disconnect (V).
7. After a successful auth OpenSSH sends a global request `hostkeys-00@openssh.com` (V), which can appear in outputs if the mapper reads it.
8. After one pty request, a second pty request on the same channel disconnects (S; V). Bitvise allows multiple.
9. CH_CLOSE after rekey kills the connection ("closing a channel after a rekey terminates the entire connection", V 6.9p1; Lenaerts did not reproduce the exact fault in 6.6p1 but found the rekey-not-state-preserving problem).
   In 8.8p1 (N, "Invalid CHANNEL_CLOSE Response"): right after OpenSSH sends its NEWKEYS it still processes messages under the old keys, answers `CH_OPEN` with open-success, then stays silent on `CH_CLOSE` and sends `CH_CLOSE` only after the client's NEWKEYS. Reported, no feedback from OpenSSH developers.
10. "Incomplete rekey" (N): OpenSSH and Bitvise process upper-layer messages received after sending their NEWKEYS and before receiving the peer's NEWKEYS, using old keys in one direction.
11. "Missing NEWKEYS" (N, OpenSSH 8.8p1 and Bitvise 8.49): a key exchange or rekey that completes without the server sending NEWKEYS.

Dropbear:

12. Answers `CH_CLOSE` with `CH_EOF` (S, N); the Dropbear maintainer confirmed and fixed it in v2022.82. Expect it to be gone in current Dropbear; this is the cleanest "still holds?" test.
13. Rekey is allowed in all states (S), including before auth.
14. Does not buffer `SR_ACCEPT` during rekey; the maintainer said buffering is not allowed by the RFC (V; RFC wording is ambiguous, see section 6).
15. "Missing SERVICE_REQUEST_USERAUTH" (N, Dropbear v2020.81): authentication can proceed without a prior ssh-userauth service request; the maintainer called it a design choice (wontfix).
16. Timing sensitivity: valid auth within about 5 ms of the previous request may fail (V).
17. Only one terminal request per channel; a second one closes the connection (S).
18. DropBear's connection layer is arguably the strictest (V).

Bitvise (closed source, Windows; not in our scope but useful as a contrast):

19. Buffers all higher-layer responses during rekey and delivers them after NEWKEYS, causing state explosion (S); later strict-KEX study had to close the connection artificially on rekey (BMBS25).
20. `NEWKEYS` directly after parameter negotiation (skipping KEX30) puts it into an unresponsive state that is closed after one minute; vendor called it an "architectural limitation" (V).
21. A second auth request produces `DEBUG+ACCEPT`-style outputs (V Fig 5.4).
22. Auth requests after `UA_SUCCESS` get `UNIMPL` (S property 11).
23. Accepts multiple terminals on one channel (S).

Other implementations from Verleg (for fingerprint context only): Tectia accepts rekey messages in any order and starts rekeying when KEXINIT, KEX30 and NEWKEYS have all arrived; CiscoSSH and PowerShell do not support multiple channels; CiscoSSH closes on any unexpected message and allows `SR_AUTH` only once.

Overall conclusion of V: every server implemented a different transport state machine, so models fingerprint implementations, and underspecification (buffering during rekey, multiple services on a channel, `CH_EOF` semantics) accounts for many differences.
V recommends that servers do not allow rekeying before auth and do not buffer.

## 3. Later work

**Fiterau-Brostean, Jonsson, Merget, de Ruiter, Sagonas, Somorovsky, DTLS (USENIX Security 2020).**
They extended TLS-Attacker with DTLS and learned 13 DTLS server (and client) implementations; they found four security vulnerabilities (including a JSSE client-authentication bypass, CVE-2020-2655) and many non-conformance bugs.
They again analysed the models by hand and confirmed by reading code.
It is the methodological bridge from FLPdRVV17 to automated bug-pattern search.
Source: https://usenix.org/conference/usenixsecurity20/presentation/fiterau-brostean.

**Fiterau-Brostean, Jonsson, Sagonas, Taaquist (NDSS 2023).**
This is the direct successor for SSH.
They intersect the learned Mealy machine with a DFA per "bug pattern" (the 11 SPIN LTL properties plus 5 new ones), turn each accepting path into a test sequence, and replay it against the real server to confirm or discard (false alarms from inexact models are filtered by replay).
They reused the SPIN 2017 artifact (mapper, learner) with a better conformance test, learned the latest Bitvise 8.49, Dropbear v2020.81 and OpenSSH 8.8p1 for two days each, and found 11 bugs in total: 7 confirm older ones and 4 are new (see items 9, 10, 11, 12, 15 above).
Reported outcomes: Dropbear acknowledged and fixed the `CH_CLOSE` bug in v2022.82, called the missing-service-request bug a design choice; Bitvise confirmed but will not fix; no feedback from OpenSSH.
Tool follow-up: SMBugFinder, ISSTA 2024 tool demo.

**Baeumer et al., Terrapin (USENIX Security 2024, CVE-2023-48795).**
A man-in-the-middle can delete messages (for example the server's `EXT_INFO`) right after the initial handshake because the unauthenticated handshake accepts extra `IGNORE` packets and sequence numbers are not reset when encryption starts; it needs ChaCha20-Poly1305 or CBC with Encrypt-then-MAC (AES-GCM is unaffected).
Sources: https://terrapin-attack.com/, arXiv 2312.12422.
Releases that added strict KEX, from memory (unverified): OpenSSH 9.6, Dropbear 2024.84, Go x/crypto 0.17.0; the Terrapin patch list at https://terrapin-attack.com/patches.html is the authoritative list.

**Strict KEX rules (draft-ietf-sshm-strict-kex-02, Damien Miller; verbatim fragments).**
- Signalling: client adds `kex-strict-c` (or pre-standard `kex-strict-c-v00@openssh.com`), server `kex-strict-s` (or `kex-strict-s-v00@openssh.com`) to `kex_algorithms`; if both sides do, "both endpoints MUST enable the transport protocol changes described below for the duration of the connection".
  "SSH implementations MUST NOT enable Strict KEX if one offers only the standard name" (i.e. the pre-standard name pairs only with the pre-standard name, standard name with standard name); implementations "SHOULD offer both".
  The indicators are valid only in the initial KEXINIT; "Their presence or absence in subsequent SSH_MSG_KEXINIT packets MUST be ignored by all parties".
- Initial KEX: "implementations MUST terminate the connection if they receive a non-KEX message during the initial key exchange"; permitted messages are "SSH_MSG_KEXINIT, SSH_MSG_NEWKEYS and the messages specific to each KEX algorithm". So `IGNORE`, `DEBUG`, `UNIMPLEMENTED`, `EXT_INFO`, `SERVICE_REQUEST` and unknown message numbers all end the connection.
- First packet: "implementations MUST verify that the SSH_MSG_KEXINIT was the first message received from the peer" (checked retroactively, since the indicator is only seen in KEXINIT); anything before it, even `IGNORE`, must fail.
- Counting: the sequence number must not wrap before the initial KEX completes; each KEX-specific message is accepted only the expected number of times (a server "MUST only accept it once", e.g. one ECDH init).
- Sequence numbers: "both the client and server MUST reset their sequence numbers at the conclusion of the initial KEX"; the send counter "MUST be reset to zero immediately after any SSH_MSG_NEWKEYS packet is sent", and the receive counter "MUST be reset after a SSH_MSG_NEWKEYS is received".
  This is per direction and happens only at the first KEX (RFC 4253 s6.4 otherwise says the number "is never reset, even if keys/algorithms are renegotiated later").
- OpenSSH's PROTOCOL file (s1.9) only points to the draft.

**Baeumer, Maehren, Brinkmann, Schwenk, "Finding SSH Strict Key Exchange Violations by State Learning" (CCS 2025). Most relevant paper for us.**
- Learned 33 models of 10 servers, one per supported KEX flow (ECDH, DH, DHGEX, RSA, PQ-hybrid): OpenSSH 9.9p2, Dropbear 2025.87, Go x/crypto/ssh 0.37.0, AsyncSSH, Bitvise, Erlang SSH, LANCOM LCOS, libssh, Tectia, TinySSH.
- Setup: LearnLib TTT learner (Kotlin), own SSH stack as mapper (TLS-Attacker style) that can emit valid or "forbidden" messages in any state, 94-symbol alphabet (all client transport/auth/connection messages from the RFCs and vendor extensions, server-only messages such as `KEX_ECDH_REPLY`, `UNIMPLEMENTED`, `IGNORE`, `EXT_INFO`, and one symbol for each of the ten unassigned message-number blocks, sent as 1-byte messages).
  Mapper resets the sequence counter and builds a new cipher state at each NEWKEYS sent or received; unavailable keys fall back to the `none` cipher.
  One fixed KEXINIT symbol per run (algorithm list fixed, KEX algorithm chosen per flow), one fixed client banner, valid cryptography only, wrong password so a `USERAUTH_SUCCESS` would indicate bypass.
- Equivalence: "happy flow mutation" (all insertions of up to n=2 symbols into the happy flow, 133 011 sequences for |F|=4, 186 121 for DHGEX) plus 10 000 random words of length 5-15. A generic random-words or Wp oracle did not terminate in reasonable time on OpenSSH (their Table 3).
- Non-determinism: cache consulted per prefix; on a conflict with replayed output they use majority voting with 13 votes (earlier work used best of three), and restart learning on cache conflicts.
  They single out OpenSSH `LoginGraceTime`: a timer that closes unauthenticated connections after a wall-clock time makes the number of inputs before closure vary, so cache conflicts never end. Raise it in our OpenSSH configuration.
- Result: Go x/crypto/ssh and OpenSSH are the only two that are compliant and close immediately.
  Dropbear 2025.87 violates strict KEX (category C4, late injection): it lifts the restrictions after sending its own NEWKEYS instead of after receiving the client's, so the client can still send messages numbered below 50 while the server is already encrypted; messages that make the server reply shift the server's sequence counter after reset, which is the Terrapin precondition.
  Other violations: Tectia (C1 and C3, plus a rogue session attack), Erlang SSH (C3, pre-auth remote code execution), LANCOM (answers unknown ids and ids >= 50 with `UNIMPLEMENTED`), TinySSH (C4, all but `IGNORE`/`DEBUG`/`DISCONNECT`), libssh (C2 on DHGEX, taint approach), AsyncSSH (C2, repeated `KEX_DH_GEX_REQUEST`).
  Bitvise and libssh use a "taint flag" and close at the end of the KEX; the authors do not count that as a violation.
- Confirmation: each violation was replayed with their SSH stack outside the learner (reach authentication after a violating trace) and reported to vendors.
- Table of violation categories (their words): C1 early message injection (before the peer's KEXINIT), C2 flow-dependent injection (only for some KEX algorithms), C3 partial hardening (blocklist instead of allowlist), C4 late injection (restrictions lifted before NEWKEYS from the peer).

**A 2026 Paderborn thesis on differential analysis of SSH state machines.**
Seen only as a search hit (https://digital.ub.uni-paderborn.de/hs/download/pdf/8260817, not read); its abstract says differential analysis of two state machines still needs expert interpretation because no reference model exists.
Also seen but not read: arXiv 2609.26358, "Formally Modeling the Terrapin Attack on SSH" (Sep 2026).
I did not find any 2023-2025 differential-testing work specifically for SSH state machines other than FJST23 and BMBS25.

## 4. What we reuse and what we do differently

### 4.1 Reuse

1. **Output abstraction by message name, concatenated.**
   One output symbol per input made of all messages received before a quiet period, in arrival order, with `IGNORE`/`DEBUG` filtered (or kept in a separate channel), and server-initiated messages such as OpenSSH's `hostkeys-00@openssh.com` global request and Tectia's banner handled explicitly.
   Add `NO_RESP` for timeout and `NO_CONN` (a sink: once the TCP connection is closed or a DISCONNECT was seen, the mapper answers `NO_CONN` locally without sending).
2. **NO_CONN sink and mapper-local outputs** (SPIN 4.2): it keeps closed-connection sequences from costing wall-clock time, and the W-method trick of dRP15 (do not extend traces past a closed connection) applies in the same way to equivalence testing in AALpy: skip any extension whose prefix already reached `NO_CONN`.
3. **Alphabet principle**: client-to-server messages only, to start; reduce the alphabet where a symbol never changes state in a pilot run, and keep a restricted and a full alphabet (Lenaerts: test the restricted model more deeply, then prune the full model to the restricted alphabet and compare).
   Our base set from SPIN: `KEXINIT`, `KEX30` (ECDH init in our case), `NEWKEYS`, `SR_AUTH`, `SR_CONN`, `UA_PK_OK`, `UA_PK_NOK`, `UA_PW_OK`, `UA_PW_NOK`, `UA_NONE`, `DISCONNECT`, `IGNORE`, `DEBUG`, `UNIMPL`, channel messages as needed.
4. **Timing**: per-SUT, per-input-type timeout, delay between inputs, local or loopback SUT.
   Choose a timeout several times the slowest normal response (dRP15 and Verleg) and record the values in the results.
   Password auth is slow on OpenSSH (2-3 s), so give it its own timeout or leave it out of the first alphabet.
   Add the BMBS25 lesson: disable or raise `LoginGraceTime` (OpenSSH), the equivalent unauthenticated-connection timeouts of Dropbear and of the Go test server (option names not checked; look them up).
5. **Cache-based non-determinism detection**: persistent store of every (input prefix, output sequence) pair, check each new observation against it, raise on conflicts, reuse as the learner's cache and for resuming a run (V, L, S; BMBS25 uses it plus voting).
   AALpy has `CacheSUL`-style wrappers; make sure we keep a conflict log and not just a silent override.
6. **Confirm each diff by replay**: FJST23 and BMBS25 both convert a model difference into a concrete trace and replay it against the live server outside the learner (and several times). dRP15 additionally read code and built an exploit.
7. **Treat unexpected-message replies as data, not as bugs**: `UNIMPL` vs `NO_RESP` vs `DISCONNECT` for the same unexpected input is an implementation choice (SPIN property 11 marked with `*`); classify diffs by RFC keyword (MUST, SHOULD, none) before calling them deviations.
8. **A rekey handled as three separate inputs**, not one atomic REKEY (Lenaerts), if rekey is in scope at all; otherwise leave rekey out and say so.
9. **Version-pin and log**: SUT version, configuration, mapper alphabet, timeouts, equivalence-oracle parameters, number of membership and equivalence queries, conflicts, wall time. The SPIN Table 4 columns are the minimum.

### 4.2 Do differently

1. **AALpy (Python) learner with a custom mapper built on our own packet layer**, not a gutted Paramiko; the mapper must be able to send valid-but-misplaced messages in any state (as in BMBS25), including server-only messages as inputs.
2. **Equivalence oracle**: use a state-prefix-biased random walk or Wp-method with a happy-flow-mutation component (BMBS25), not only exhaustive k = 2; the 2017 result that k = 2 exhaustive missed a rekey bug is a warning.
   Report the confidence honestly (random testing gives no guarantee).
3. **Strict KEX as an explicit factor**: learn each SUT once with strict KEX offered by the mapper and once without, because strict KEX changes pre-NEWKEYS behaviour (OpenSSH 9.6+, Dropbear 2024.84+, Go x/crypto 0.17+ negotiate it only if the client offers `kex-strict-c-v00@openssh.com`).
   Also include `IGNORE`, `DEBUG`, `UNIMPL`, `EXT_INFO` (RFC 8308) and unknown message numbers in the alphabet, which SPIN excluded.
4. **Do not fix a channel limit by hiding it in the mapper if possible**: SPIN's `CH_MAX`/`CH_NONE` added many states. We stay in transport and auth layers, so we avoid it; if we add connection-layer inputs, use a 1-channel cap but record it as a model limitation.
5. **Differential analysis across implementations, not per-RFC property checks only**: align models by trace equivalence and report shortest distinguishing traces, then judge each against the RFC clauses in section 5.
   The previous papers mostly checked one implementation at a time against the RFC properties or compared by eye; the Paderborn thesis notes that this still needs expert judgement.
6. **Current versions and Go x/crypto/ssh**, which none of the SSH-learning papers before BMBS25 covered (BMBS25 covers it only for strict-KEX handshakes with a wrong password).
7. **Parameter handling**: keep one fixed KEXINIT algorithm list and one fixed banner (as BMBS25) and state it, because the banner can switch compatibility modes (e.g. OpenSSH `compat` flags, Dropbear) and algorithm lists change flows.
8. **Controlled non-determinism**: handle wall-clock timers explicitly (login grace time, auth attempt limits such as MaxAuthTries, and RFC 4252 s4's recommended 20-attempt limit, which closes the connection after repeated `UA_*_NOK` inputs), since a long trace of failed auth attempts will hit them and look like a state.
9. **Replay with vote**: replay each flagged distinguishing trace at least 3 times (BMBS25 used up to 13 when it mattered) on fresh connections, and keep a trace file under `results/` so that the claim can be rechecked.
10. **Re-check the previous deviations list (section 2.9) as a regression suite**: for each numbered item, write the exact input sequence from the published model (the SPIN repository has the models) and run it against current versions, so we can say which findings persist.

## 5. RFC clauses for judging handshake-ordering disagreements

Quoted from the plain-text RFCs at rfc-editor.org (https://www.rfc-editor.org/rfc/rfc4253.txt, rfc4252.txt, rfc4254.txt, rfc8308.txt); line wrapping removed.

### RFC 4253 (transport)

**s7.1 Algorithm Negotiation (what may be sent between KEXINIT and NEWKEYS).**
"Once a party has sent a SSH_MSG_KEXINIT message for key exchange or re-exchange, until it has sent a SSH_MSG_NEWKEYS message (Section 7.3), it MUST NOT send any messages other than: o Transport layer generic messages (1 to 19) (but SSH_MSG_SERVICE_REQUEST and SSH_MSG_SERVICE_ACCEPT MUST NOT be sent); o Algorithm negotiation messages (20 to 29) (but further SSH_MSG_KEXINIT messages MUST NOT be sent); o Specific key exchange method messages (30 to 49)."
"The provisions of Section 11 apply to unrecognized messages."
"Note, however, that during a key re-exchange, after sending a SSH_MSG_KEXINIT message, each party MUST be prepared to process an arbitrary number of messages that may be in-flight before receiving a SSH_MSG_KEXINIT message from the other party."
This restricts what a party sends, not what it accepts; the RFC gives no rule that a server must reject a received out-of-order message.
That gap is why OpenSSH (pre-strict) answers any first packet with a KEXINIT and why Verleg's "liberal acceptance" findings are not RFC violations in the MUST sense.
Same section, guessed packets: "If the other party's guess was wrong, and this field was TRUE, the next packet MUST be silently ignored, and both sides MUST then act as determined by the negotiated key exchange method."
Same section: "If no algorithm satisfying all these conditions can be found, the connection fails, and both sides MUST disconnect."

**s7.3 Taking Keys Into Use.**
"Key exchange ends by each side sending an SSH_MSG_NEWKEYS message. This message is sent with the old keys and algorithms. All messages sent after this message MUST use the new keys and algorithms."
"When this message is received, the new keys and algorithms MUST be used for receiving."
(Basis for NDSS "Missing NEWKEYS" and "Incomplete rekey".)

**s9 Key Re-Exchange.**
"Key re-exchange is started by sending an SSH_MSG_KEXINIT packet when not already doing a key exchange (as described in Section 7.1). When this message is received, a party MUST respond with its own SSH_MSG_KEXINIT message, except when the received SSH_MSG_KEXINIT already was a reply."
"More application data may be sent after the SSH_MSG_NEWKEYS packet has been sent; key exchange does not affect the protocols that lie above the SSH transport layer."
Rekey is thus not optional for a server: OpenSSH refusing KEXINIT before auth (as seen in 6.9) is at odds with "MUST respond", though 4253 does not say in which service states it applies.

**s6.4 Data integrity (sequence numbers).**
"The sequence_number is initialized to zero for the first packet, and is incremented after every packet (regardless of whether encryption or MAC is in use). It is never reset, even if keys/algorithms are renegotiated later."
Strict KEX is the one sanctioned exception (reset at the initial NEWKEYS).

**s10 Service Request.**
"If the server rejects the service request, it SHOULD send an appropriate SSH_MSG_DISCONNECT message and MUST disconnect."
"If the server supports the service (and permits the client to use it), it MUST respond with the following: byte SSH_MSG_SERVICE_ACCEPT, string service name."
"Note that after a key exchange with implicit server authentication, the client MUST wait for a response to its service request message before sending any further data."
Not covered: a second service request, or a service request after auth (OpenSSH answers `DISCONNECT` for `ssh-connection` before auth, answers `UNIMPL` or accepts a repeat, CiscoSSH disconnects on a repeat).

**s11.1 Disconnection.**
"This message causes immediate termination of the connection. All implementations MUST be able to process this message; they SHOULD be able to send this message."
"The sender MUST NOT send or receive any data after this message, and the recipient MUST NOT accept any data after receiving this message."
(Basis for property 6 and for `NO_CONN` being an absorbing state.)

**s11.2 Ignored Data.**
"All implementations MUST understand (and ignore) this message at any time (after receiving the identification string). No implementation is required to send them."
So a server must tolerate `IGNORE` at any time (and so the model should show `NO_RESP` self-loops) unless strict KEX is negotiated, where the draft overrides this during the initial KEX.

**s11.3 Debug.**
"All implementations MUST understand this message, but they are allowed to ignore it."

**s11.4 Reserved Messages / Unimplemented.**
"An implementation MUST respond to all unrecognized messages with an SSH_MSG_UNIMPLEMENTED message in the order in which the messages were received. Such messages MUST be otherwise ignored."
"byte SSH_MSG_UNIMPLEMENTED, uint32 packet sequence number of rejected message".
A reply of `UNIMPL` to an unknown message number is therefore required, and a closed connection is not RFC-compliant on its face (strict KEX again overrides this during the initial KEX).
Message that are recognised but out of place (for instance `KEX30` in the wrong state, `NEWKEYS` without KEX) are not covered by this clause, which is why they vary.

**s12 Message numbers.**
SSH_MSG_DISCONNECT 1, IGNORE 2, UNIMPLEMENTED 3, DEBUG 4, SERVICE_REQUEST 5, SERVICE_ACCEPT 6, KEXINIT 20, NEWKEYS 21; "Note that numbers 30-49 are used for kex packets. Different kex methods may reuse message numbers in this range."
RFC 8308 adds SSH_MSG_EXT_INFO = 7.
Use these ranges to generate "undefined message" inputs (take the unassigned blocks from the IANA SSH message-number registry, which was not fetched for this note).

### RFC 4252 (authentication)

**s4 Framework.**
"The 'none' method is reserved, and MUST NOT be listed as supported. However, it MAY be sent by the client. The server MUST always reject this request, unless the client is to be granted access without any authentication, in which case, the server MUST accept this request."
"The server SHOULD have a timeout for authentication and disconnect if the authentication has not been accepted within the timeout period. The RECOMMENDED timeout period is 10 minutes. Additionally, the implementation SHOULD limit the number of failed authentication attempts a client may perform in a single session (the RECOMMENDED limit is 20 attempts). If the threshold is exceeded, the server SHOULD disconnect."

**s5 Authentication Requests.**
"The 'user name' and 'service name' are repeated in every new authentication attempt, and MAY change. The server implementation MUST carefully check them in every message, and MUST flush any accumulated authentication states if they change. If it is unable to flush an authentication state, it MUST disconnect if the 'user name' or 'service name' changes."
(So OpenSSH's and Tectia's refusal to change usernames is allowed only as "disconnect"; silently failing is not.)
"If the requested service is not available, the server MAY disconnect immediately or at any later time. Sending a proper disconnect message is RECOMMENDED. In any case, if the service does not exist, authentication MUST NOT be accepted."
"While there is usually little point for clients to send requests that the server does not list as acceptable, sending such requests is not an error, and the server SHOULD simply reject requests that it does not recognize."
"The client MAY at any time continue with a new SSH_MSG_USERAUTH_REQUEST message, in which case the server MUST abandon the previous authentication attempt and continue with the new one."

**s5.1 Responses.**
"If the server rejects the authentication request, it MUST respond with the following: byte SSH_MSG_USERAUTH_FAILURE, name-list authentications that can continue, boolean partial success."
"SSH_MSG_USERAUTH_SUCCESS MUST be sent only once. When SSH_MSG_USERAUTH_SUCCESS has been sent, any further authentication requests received after that SHOULD be silently ignored."
"Any non-authentication messages sent by the client after the request that resulted in SSH_MSG_USERAUTH_SUCCESS being sent MUST be passed to the service being run on top of this protocol. Such messages can be identified by their message numbers (see Section 6)."
"The client MAY send several authentication requests without waiting for responses from previous requests. The server MUST process each request completely and acknowledge any failed requests with a SSH_MSG_USERAUTH_FAILURE message before processing the next request."
Note the two strengths: "MUST be sent only once" (hard) versus "SHOULD be silently ignored" (soft). OpenSSH and Bitvise reply `UNIMPL` after success (SHOULD violation), which is the SPIN property 11 deviation. Judge it as a soft deviation, not as a bug.

**s5.2 The "none" request.**
"If no authentication is needed for the user, the server MUST return SSH_MSG_USERAUTH_SUCCESS. Otherwise, the server MUST return SSH_MSG_USERAUTH_FAILURE and MAY return with it a list of methods that may continue in its 'authentications that can continue' value."

**s5.3 Completion.**
"Authentication is complete when the server has responded with SSH_MSG_USERAUTH_SUCCESS. All authentication related messages received after sending this message SHOULD be silently ignored."

**s6 Message numbers (ordering rule).**
"Message numbers of 80 and higher are reserved for protocols running after this authentication protocol, so receiving one of them before authentication is complete is an error, to which the server MUST respond by disconnecting, preferably with a proper disconnect message sent to ease troubleshooting."
"After successful authentication, such messages are passed to the higher-level service."
This is the MUST clause that makes "channel message before auth" a disconnect in all conforming servers (message ids 80-127 in the model).
Auth messages are 50-53 (REQUEST, FAILURE, SUCCESS, BANNER) and 60-79 method-specific, server-to-client.

### RFC 4254 (connection), used for property 12

**s5.3 Closing a Channel.**
"Upon receiving this message, a party MUST send back an SSH_MSG_CHANNEL_CLOSE unless it has already sent this message for the channel."
"No explicit response is sent to this message [SSH_MSG_CHANNEL_EOF]."
(Dropbear's `CH_EOF` in reply to `CH_CLOSE` violated the first quote in 2014.65 and v2020.81.)

### RFC 8308 (extension negotiation)

**s2.1.** Indicator names go "to the field kex_algorithms in the SSH_MSG_KEXINIT message sent by the application in the first key exchange": "When acting as server: 'ext-info-s'", "When acting as client: 'ext-info-c'".
**s2.2.** "If a client or server offers 'ext-info-c' or 'ext-info-s' respectively, it MUST be prepared to accept an SSH_MSG_EXT_INFO message from the peer." "Implementations MUST NOT send an incorrect indicator name for their role. Implementations MAY disconnect if the counterparty sends an incorrect indicator."
**s2.4.** "If a client sends SSH_MSG_EXT_INFO, it MUST send it as the next packet following the client's first SSH_MSG_NEWKEYS message to the server." "If a server sends SSH_MSG_EXT_INFO, it MAY send it at zero, one, or both of the following opportunities: as the next packet following the server's first SSH_MSG_NEWKEYS; immediately preceding the server's SSH_MSG_USERAUTH_SUCCESS."
Relevance: a server can legitimately emit `EXT_INFO` between `NEWKEYS` and the service accept, and just before `USERAUTH_SUCCESS`, so the output abstraction must either filter or tag it (OpenSSH sends `server-sig-algs` this way); otherwise it creates spurious "differences".
Under strict KEX, an `EXT_INFO` sent by a client before its NEWKEYS must be rejected (it is a non-KEX message), while the after-NEWKEYS position is allowed.

### How to use these clauses

1. A disagreement between two servers on an input the RFC does not constrain (examples: KEX30 in the wrong state, a second SERVICE_REQUEST, NEWKEYS before KEX30, rekey before auth) is a divergence, not a violation. Report it with the clause that is silent.
2. A disagreement where one server's behaviour contradicts a MUST/MUST NOT above (examples: `CH_EOF` instead of `CH_CLOSE`; accepting auth without a service request is not a MUST problem for 4253 s10 but is for 4252 s5 "service ... MUST NOT be accepted" if the service name is unknown) is a violation candidate: confirm by replay, then report.
3. A disagreement on a SHOULD (silence after `USERAUTH_SUCCESS`, disconnect after rejecting a service) is a soft deviation.
4. For strict-KEX runs, use draft-ietf-sshm-strict-kex rules first, then the RFCs.

## 6. Open points to settle before the experiments

- RFC 4253 s7.1 vs buffering: "MUST NOT send any messages other than" can mean "hold back and send after NEWKEYS" (Bitvise, Tectia, PowerShell buffer) or "drop" (OpenSSH, Dropbear, CiscoSSH). The RFC text is ambiguous. We decide the label (`BUFFERED` symbol vs plain output) before learning, as SPIN did.
- I could not extract the NDSS 2023 appendix details for "Invalid SERVICE_REQUEST_USERAUTH Response" and "Missing NEWKEYS"; read Section VIII and the Zenodo artifact before writing those tests.
- Not verified: exact first releases that implement strict KEX in Dropbear and Go x/crypto (see section 3), and the IANA list of unassigned message-number blocks.
- Not read: Verleg's property-by-property transport findings for Dropbear's "unresp" state (Figure 5.3 shows none; the Tectia text says DropBear has one), and the SPIN public models, which should be downloaded and replayed as the regression suite in section 4.2 item 10.
