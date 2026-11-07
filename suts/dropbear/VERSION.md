# Dropbear SUT

- Server: Dropbear 2025.88, Alpine package `dropbear=2025.88-r1` (`dropbear -V` prints `Dropbear v2025.88`).
- Banner: `SSH-2.0-dropbear_2025.88`.
- Base image: `alpine:3.22` (3.22.8), digest `sha256:bfe7ceb9f09ec0566c48fb93356e45a47a00be5a1dd14fa5b909e7709c66b034`.
- Not built from source.
  Upstream tarball `dropbear-2025.88.tar.bz2` (sha256 `783f50ea27b17c16da89578fafdb6decfa44bb8f6590e5698a4e4d3672dc53d4`) was only read to find the compile-time defaults below.
- Image `psm-dropbear:pinned`, container `psm-dropbear`, `127.0.0.1:2202` on the box.
- Build and start: `./gx bash suts/dropbear/run.sh` (or `ssh gx10 'bash -s' < suts/dropbear/run.sh` once synced).

## Config

- Command: `dropbear -F -E -w -p 22 -r /etc/dropbear/dropbear_ed25519_host_key`.
- Only an ed25519 host key exists. Host key is generated at image build, so it is stable for the image and changes if the image is rebuilt without cache.
- Password auth enabled (default), root login disabled (`-w`), user `tester` / `correct-horse-battery` (shell `/bin/sh`).
- Everything else at defaults.
- Container limits: 64 MB, 0.5 CPU.
- Logs: `ssh gx10 'docker logs -f psm-dropbear'` (stderr; lines like `Child connection from ...`, `Bad password attempt`, `Exit before auth`).

## Defaults that matter to the state machine (upstream 2025.88 source)

- Max auth tries: `MAX_AUTH_TRIES 10` (`-T`, confirmed by `dropbear -h`). Connection is dropped once `failcount >= 10` (svr-auth.c:430).
- Auth timeout: `AUTH_TIMEOUT 300` s from connect, applied until auth is done (sysoptions.h, common-session.c).
- Failed-auth delay (svr-auth.c ~385-424): the SSH_MSG_USERAUTH_FAILURE reply is delayed so total time since the auth request began is `250 ms + rand % 100 ms`, i.e. 250-350 ms (comment says 300 ms +-50 ms), minus time already spent (password hash).
  The "none" method has no failure delay (line ~141).
- `MAX_UNAUTH_PER_IP 5`: a 6th concurrent unauthenticated connection from the same IP is dropped immediately (svr-main.c:294). `MAX_UNAUTH_CLIENTS 30` globally.
  All box-local clients appear from 172.17.0.1 (docker bridge), so they share one IP.
  A connection counts as unauthenticated until auth succeeds, so closed-but-not-yet-reaped connections can matter in rapid reconnect loops.
- `UNAUTH_CLOSE_DELAY 0` (no delay before closing unauthenticated sessions).
- Keepalive and idle timeout: 0 (off).
- Alpine may patch compile options; the values above are from upstream defaults, cross-checked only for `-T`, `-K`, `-I`, `-W` via `dropbear -h`.

## Server KEXINIT proposal (from `ssh -vvv`, OpenSSH client on the box)

- kex_algorithms: `sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,mlkem768x25519-sha256,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group14-sha256,kexguess2@matt.ucc.asn.au,kex-strict-s-v00@openssh.com`
- server_host_key_algorithms: `ssh-ed25519`
- encryption (both directions): `chacha20-poly1305@openssh.com,aes256-ctr,aes128-ctr`
- mac (both directions): `hmac-sha2-256`
- compression (both directions): `none`
- languages: empty.
- Offers curve25519-sha256, ssh-ed25519, aes128-ctr, hmac-sha2-256, and `kex-strict-s-v00@openssh.com` (strict KEX is offered).
- The server does not list `ext-info-s`.

## Verification (2026-11-07, on the box)

- paramiko `tester` / `correct-horse-battery`: login OK, `id; echo hello` ran as uid 1000, remote version `SSH-2.0-dropbear_2025.88`, host key `ssh-ed25519`.
- Wrong password: `AuthenticationException`; log shows `Bad password attempt for 'tester'`.

## Changes at 13:05 for the published mapper (supersede the host-key notes above)

The published Fiterau-Brostean mapper (vendor/) verifies only RSA host signatures and implements only finite-field DH key exchange.
So the image now ALSO has an RSA (3072-bit) host key, and the mapper negotiates `diffie-hellman-group14-sha256` + `rsa-sha2-256` + `aes128-ctr` + `hmac-sha2-256`.
The mapper does not advertise `kex-strict-c-v00@openssh.com`, so strict KEX is never negotiated in our experiments.
The learner's throwaway test public key is installed by `suts/authorize.sh` after each start (needed for UA_PK_OK).
