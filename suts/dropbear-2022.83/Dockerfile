# Dropbear 2022.83: the version of the published ssh-fuzzer Dropbear server model (vendor/.../DROPBEAR_SERVER_1683485573153).
# Used only to validate the harness by learning the same version the published model was learned on (Alpine 3.17 package).
FROM alpine@sha256:8fc3dacfb6d69da8d44e42390de777e48577085db99aa4e4af35f483eb08b989
RUN apk add --no-cache dropbear=2022.83-r1 \
 && adduser -D -s /bin/sh tester \
 && echo 'tester:correct-horse-battery' | chpasswd \
 && mkdir -p /etc/dropbear /home/tester/.ssh && chown tester:tester /home/tester/.ssh && chmod 700 /home/tester/.ssh \
 && dropbearkey -t rsa -s 3072 -f /etc/dropbear/dropbear_rsa_host_key
EXPOSE 22
# RSA host key: the published mapper only verifies ssh-rsa / rsa-sha2-256 host signatures.
CMD ["dropbear", "-F", "-E", "-w", "-p", "22", "-r", "/etc/dropbear/dropbear_rsa_host_key"]
