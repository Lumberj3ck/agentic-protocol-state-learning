Onboarded **Apache MINA SSHD 2.20.1**, the latest stable release, in `targets/mina-sshd/`.

Validation: **16 passed, 1 skipped**. The skipped test applies only to OpenSSH. Required algorithms, strict KEX, password authentication, and exec exit status 0 were confirmed.

Fixed an initial host-key generation delay by generating the key before listening. No unresolved behavior differences or known mapper-issue failures remain. Docker validation required `DOCKER_BUILDKIT=0`.

[Per-test report](targets/mina-sshd/README.md) · [Test output](targets/mina-sshd/test-output.txt)