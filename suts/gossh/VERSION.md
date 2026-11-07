# gossh SUT

- Library: golang.org/x/crypto v0.58.0 (newest on proxy.golang.org on 2026-11-07; tag time 2026-10-09; includes strict KEX).
- Transitive: golang.org/x/sys v0.49.0 (go.sum pins hashes).
- Go: go1.26.0 linux/arm64 (x/crypto v0.58.0 requires go >= 1.26.0; the golang:1.23-bookworm image fetches the toolchain via GOTOOLCHAIN=auto, pinned by `toolchain go1.26.0` in go.mod).
- Image: `psm-gossh:pinned`, id sha256:4dc1b0f2b355e61a77e5992fc69f57dbd75d496455533e2fc421f0184d0b5414, ~103 MB.
  Build: golang:1.23-bookworm, runtime debian:bookworm-slim (debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc).
- Container `psm-gossh`, 127.0.0.1:2203 -> :22, `--restart unless-stopped`, 128 MB, 1 CPU.
- Start: `./gx bash suts/gossh/run.sh`.
- Host key: ssh-ed25519, generated at every process start (new key on each container restart; do not pin it in clients).
- Banner: `SSH-2.0-Go` (library default; sent with no comments).

## Behaviour of main.go
- Password auth accepts only `tester` / `correct-horse-battery`; publickey callback rejects everything.
- Advertised auth methods: `password,publickey`.
- After auth: "session" channels accepted; `pty-req`/`shell`/`exec` get a success reply; other session requests get failure.
  `exec` writes `hello from gossh\n`, sends exit-status 0 and closes the channel.
  Other channel types are rejected with UnknownChannelType.
- One goroutine per TCP connection.

## Server KEXINIT (from `ssh -vvv -p 2203 tester@127.0.0.1 true` on the box, OpenSSH client; all library defaults)
- kex: mlkem768x25519-sha256,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,kex-strict-s-v00@openssh.com
- host key: ssh-ed25519
- ciphers (both directions): aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr
- MACs (both): hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96
- compression: none
- languages: empty

Confirmed offered: curve25519-sha256, ssh-ed25519, aes128-ctr, hmac-sha2-256, kex-strict-s-v00@openssh.com.
No `ext-info-s` is offered in kex, so no SSH_MSG_EXT_INFO from this server.
The server sends KEXINIT first and sets no `first_kex_packet_follows`.

## Verification (on the box)
- paramiko (5.1.0), tester/correct-horse-battery: login ok, `exec true` returned `hello from gossh`, exit status 0.
- paramiko with wrong password: AuthenticationException.

## Logs
`ssh gx10 docker logs psm-gossh` (stderr).
Lines: `handshake ok from <addr> user=.. client=".."`, `handshake error from <addr>: <err>`, `connection closed from <addr>`.
Observed errors: `[bad credentials]` (auth loop ended with the callback error after a client disconnect), `[ssh: no auth passed yet]` (client sent none-auth then disconnected).
Note a handshake error is logged only when NewServerConn returns, i.e. when the connection ends before auth succeeds.

## Library defaults relevant to the state machine
- MaxAuthTries default 6 (`server.go:356`); after 6 failures the server disconnects (the check is `authFailures >= MaxAuthTries`).
  Failed "none" and failed public-key queries (no signature) do not count toward the limit (see comment at `server.go:649`).
- Auth failure: SSH_MSG_USERAUTH_FAILURE listing `password,publickey`; no sleep/delay calls in server.go.
- Server never sends a USERAUTH_BANNER.
- Algorithms and all other settings are unmodified.

## Non-determinism candidates
- Host key changes on each container restart (fresh key per start).
- KEX uses fresh ephemeral keys and random cookie each connection, so bytes differ per run, but the message sequence should not.
- The server is a goroutine per connection with no cross-connection state, so repeated short connections should be independent.
- Log lines are written only at connection end; abrupt client closes yield different error text depending on the phase.
