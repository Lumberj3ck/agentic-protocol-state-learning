FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd && useradd -m test && echo 'test:test' | chpasswd
RUN printf 'PasswordAuthentication yes\nKbdInteractiveAuthentication no\nUsePAM no\nLogLevel ERROR\n' > /etc/ssh/sshd_config.d/smlearn.conf
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
