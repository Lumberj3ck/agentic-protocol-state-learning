FROM alpine:edge
RUN apk add --no-cache openssh-server && ssh-keygen -A \
 && adduser -D -s /bin/sh test && echo 'test:test' | chpasswd \
 && printf 'PasswordAuthentication yes\nKbdInteractiveAuthentication no\nLogLevel ERROR\n' >> /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
