# Dropbear 2020.81: the version analysed by Fiterau-Brostean et al. (NDSS 2023). Used only to validate
# the harness by reproducing a published finding. Alpine 3.13 shipped it as a package (no 2020-era C build).
FROM alpine@sha256:469b6e04ee185740477efa44ed5bdd64a07bbdd6c7e5f5d169e540889597b911
RUN apk add --no-cache dropbear=2020.81-r0 \
 && adduser -D -s /bin/sh tester \
 && echo 'tester:correct-horse-battery' | chpasswd \
 && mkdir -p /etc/dropbear /home/tester/.ssh && chown tester:tester /home/tester/.ssh && chmod 700 /home/tester/.ssh \
 && dropbearkey -t rsa -s 3072 -f /etc/dropbear/dropbear_rsa_host_key
EXPOSE 22
# RSA host key: the published mapper only verifies ssh-rsa / rsa-sha2-256 host signatures.
CMD ["dropbear", "-F", "-E", "-w", "-p", "22", "-r", "/etc/dropbear/dropbear_rsa_host_key"]
