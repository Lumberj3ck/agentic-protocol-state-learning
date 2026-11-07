# Dropbear SSH server, pinned. Base image pinned by digest (alpine:3.22, 3.22.8).
FROM alpine:3.22@sha256:bfe7ceb9f09ec0566c48fb93356e45a47a00be5a1dd14fa5b909e7709c66b034
RUN apk add --no-cache dropbear=2025.88-r1 \
 && adduser -D -s /bin/sh tester \
 && echo 'tester:correct-horse-battery' | chpasswd \
 && mkdir -p /etc/dropbear \
 && dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key
EXPOSE 22
# -F foreground, -E log to stderr, -w no root login; password auth is on by default (no -s/-g).
# Only the ed25519 host key is loaded (-r); no other host key types exist in the image.
CMD ["dropbear", "-F", "-E", "-w", "-p", "22", "-r", "/etc/dropbear/dropbear_ed25519_host_key"]
