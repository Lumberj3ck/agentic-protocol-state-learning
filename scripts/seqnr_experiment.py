"""Does a server reset its receive sequence number on a NEWKEYS that is not part of a key exchange?

Variants after a completed handshake, for each target:
  A  strict KEX on,  client keeps its sequence number after the stray NEWKEYS
  B  strict KEX off, client keeps its sequence number
  C  strict KEX on,  client resets its own outgoing sequence number to 0 after the stray NEWKEYS
If A fails, B succeeds and C succeeds, the server reset its receive counter without new keys.
"""
from smlearn import testbed
from smlearn.ssh.mapper import SSHMapper

WORDS = {
    "pre-auth refused rekey": (["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "KEXINIT", "KEX30", "NEWKEYS"], "UA_PW_OK"),
    "pre-auth bare NEWKEYS": (["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "NEWKEYS"], "UA_PW_OK"),
    "post-auth bare NEWKEYS": (["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "UA_PW_OK", "NEWKEYS"], "CH_OPEN"),
}

import sys
for name in (sys.argv[1:] or ["openssh", "dropbear", "asyncssh"]):
    inst = testbed.start(testbed.load_target(name))
    try:
        for label, (prefix, probe) in WORDS.items():
            row = []
            for variant, strict, reset in (("A", True, False), ("B", False, False), ("C", True, True)):
                m = SSHMapper(inst.host, inst.port, timeout=0.4, quiet=0.1, strict_kex=strict)
                outs = set()
                for _ in range(3):
                    m.reset()
                    pre = [m.step(i) for i in prefix]
                    if reset:
                        m.outgoing.sequence = 0
                    outs.add((pre[-1], m.step(probe)))
                m.close()
                (last, probe_out), = outs if len(outs) == 1 else [("NONDET", str(outs))]
                row.append(f"{variant}: NEWKEYS->{last}, {probe}->{probe_out}")
            print(f"{name:9} {label:24} | " + " | ".join(row))
    finally:
        inst.stop()
