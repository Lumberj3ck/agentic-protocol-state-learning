# mina-sshd SUT (stream B1)

- Version: Apache MINA SSHD 2.20.1 (Maven Central org.apache.sshd:sshd-core:2.20.1 + slf4j-simple 1.7.36; maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237 build, eclipse-temurin:21-jre-alpine@sha256:ac05c3c42b7c2f1a52c9bd52f01041fa1958231b15ebeae7420429cbc5baf474 runtime).
- Source of the Dockerfile/server code: adapted from vendor/agentic-protocol-state-learning/targets/mina-sshd (Apache-2.0, teammate's repo); changes: user tester / correct-horse-battery, publickey via /etc/psm/authorized_keys (installed by suts/b1/run.sh from keys/id_rsa.pub), RSA host key, diffie-hellman-group14-sha256 / rsa-sha2-256 / aes128-ctr / hmac-sha2-256 all offered by library defaults.
- Image: `psm-b1-mina-sshd:pinned` (sha256:71c7dda50a21...). Container `psm-b1-mina-sshd`, 127.0.0.1:2306->22. Mapper container `psm-mapper-b1-mina-sshd` on 8306.
- Start: `bash suts/b1/run.sh mina-sshd 2306` on the box (checks free disk >= 8 GB). Verify: `.venv/bin/python suts/b1/verify.py 2306`.
- Notes: SimpleGeneratorHostKeyProvider RSA-3072; password + AuthorizedKeyEntriesPublickeyAuthenticator reading /etc/psm/authorized_keys on each attempt. Banner APACHE-SSHD-2.20.1.
- Server KEXINIT (OpenSSH client -vvv, server proposal is the second KEX/hostkey/cipher/MAC lines): `results/v2/B1/kexinit_mina-sshd.txt`.
