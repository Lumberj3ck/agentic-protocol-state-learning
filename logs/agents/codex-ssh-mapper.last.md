Implemented separate wire encoding, packet/crypto, and mapper modules in `src/smlearn/ssh/`.

Validation:
- 10 offline tests pass.
- Happy-path tests pass for OpenSSH and Dropbear.
- AsyncSSH sends `IGNORE+SERVICE_ACCEPT` after `SR_AUTH`; the test requires exactly `SERVICE_ACCEPT`.

Stopped as instructed: the contract requires reporting every received message, including `IGNORE`. A separate trace confirmed AsyncSSH sends an empty IGNORE packet (`0200000000`) before SERVICE_ACCEPT. Suppressing it would violate the spec. The remaining validation tests were not run.

Choices left open: wrong passwords use a `-wrong` suffix; client channel id is 0. No protected files were changed.