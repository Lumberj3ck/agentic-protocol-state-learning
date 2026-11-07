# OpenSSH SUT

- Package: `openssh-server=10.0_p1-r11` (Alpine 3.22 main), pinned exactly in the Dockerfile.
- Server banner: `SSH-2.0-OpenSSH_10.0` (OpenSSL 3.5.9; privsep split into sshd-session / sshd-auth).
- Base image: `alpine:3.22@sha256:bfe7ceb9f09ec0566c48fb93356e45a47a00be5a1dd14fa5b909e7709c66b034`.
- Container `psm-openssh`, image `psm-openssh:pinned`, bound to 127.0.0.1:2201 on the box (`--memory 128m --cpus 1`).
- Start: `./gx bash suts/openssh/run.sh` (idempotent).
- Server debug log (LogLevel DEBUG3, `sshd -D -e`): `ssh gx10 docker logs psm-openssh`.
- Account `tester` / `correct-horse-battery`.
  Single host key: ssh-ed25519, generated at build time (so fixed per image build; rebuilding from cache keeps it).

## Server KEXINIT proposal (observed with OpenSSH_9.6 client `-vvv`)

- kex: mlkem768x25519-sha256, sntrup761x25519-sha512, sntrup761x25519-sha512@openssh.com, curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521, ext-info-s, kex-strict-s-v00@openssh.com
- host key: ssh-ed25519
- ciphers (both directions): chacha20-poly1305@openssh.com, aes128-gcm@openssh.com, aes256-gcm@openssh.com, aes128-ctr, aes192-ctr, aes256-ctr
- MACs (both directions): umac-64-etm@openssh.com, umac-128-etm@openssh.com, hmac-sha2-256-etm@openssh.com, hmac-sha2-512-etm@openssh.com, hmac-sha1-etm@openssh.com, umac-64@openssh.com, umac-128@openssh.com, hmac-sha2-256, hmac-sha2-512, hmac-sha1
- compression: none, zlib@openssh.com
- languages: empty; first_kex_follows 0.

Confirmed offered: curve25519-sha256, ssh-ed25519, aes128-ctr, hmac-sha2-256.
Strict KEX (Terrapin) IS offered: `kex-strict-s-v00@openssh.com`.
`ext-info-s` is also offered, so a client that sends `ext-info-c` gets SSH_MSG_EXT_INFO after NEWKEYS.

## Config deviations from defaults (`sshd_config`)

- `HostKey` ed25519 only: same host key type across all SUTs.
- `PasswordAuthentication yes`, `KbdInteractiveAuthentication no`, `UsePAM no`: password-only, no PAM side effects or delays.
- `PermitRootLogin no`: default-equivalent, explicit.
- `PerSourcePenalties no`: since 9.8 the default penalises repeated auth failures / early disconnects per source IP and would eventually block the learner.
- `MaxStartups 100:30:200`: default 10:30:100 could drop connections during rapid short test connections.
- `LogLevel DEBUG3`: full packet-level log on stderr.

## Defaults that matter to the state machine (unchanged)

- `MaxAuthTries 6`: the 6th failed authentication gets the failure reply, then the server disconnects (observed: attempts 1-5 on one connection returned failure with the session alive, attempt 6 killed it).
  Bounds the number of auth queries per connection.
- `LoginGraceTime 120`: unauthenticated connections are dropped after 120 s.
- `MaxSessions 10`.
- Auth failure delay: no PAM, so no fixed multi-second delay.
  Observed latency of a failed password is about 10 ms and 60 sequential failed logins (new connection each) took 3.9 s total, no throttling.
  (OpenSSH does apply a small randomised/constant-time delay for failing password auth; it is not visible at this scale.)
- `none` auth probe returns failure with methods `publickey,password`.
- Strict KEX: when both sides announce it, sequence numbers reset at NEWKEYS and unexpected messages during KEX cause disconnect; this will shape the learned model.

## Changes at 13:05 for the published mapper (supersede the host-key notes above)

The published Fiterau-Brostean mapper (vendor/) verifies only RSA host signatures and implements only finite-field DH key exchange.
So the image now ALSO has an RSA (3072-bit) host key, and the mapper negotiates `diffie-hellman-group14-sha256` + `rsa-sha2-256` + `aes128-ctr` + `hmac-sha2-256`.
The mapper does not advertise `kex-strict-c-v00@openssh.com`, so strict KEX is never negotiated in our experiments.
The learner's throwaway test public key is installed by `suts/authorize.sh` after each start (needed for UA_PK_OK).
OpenSSH-specific: `KexAlgorithms +diffie-hellman-group14-sha256` (OpenSSH 10.0 disables modp DH in sshd by default) and `HostKey /etc/ssh/ssh_host_rsa_key`.
