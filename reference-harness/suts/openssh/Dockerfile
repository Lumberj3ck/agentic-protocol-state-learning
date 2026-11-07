# OpenSSH server SUT, pinned. Base digest recorded in VERSION.md.
FROM alpine:3.22@sha256:bfe7ceb9f09ec0566c48fb93356e45a47a00be5a1dd14fa5b909e7709c66b034
RUN apk add --no-cache openssh-server=10.0_p1-r11 \
 && adduser -D -s /bin/sh tester \
 && echo 'tester:correct-horse-battery' | chpasswd \
 && ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key \
 && ssh-keygen -q -t rsa -b 3072 -N "" -f /etc/ssh/ssh_host_rsa_key \
 && mkdir -p /run/sshd
COPY sshd_config /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
