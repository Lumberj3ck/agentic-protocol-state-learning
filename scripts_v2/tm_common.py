"""Shared helpers for stream A: run the teammate's mapper (vendor/agentic-protocol-state-learning, read-only)
against OUR SUT containers on 127.0.0.1 (no testbed, no container start/stop)."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TM_SRC = os.path.join(ROOT, "vendor", "agentic-protocol-state-learning", "src")
if TM_SRC not in sys.path:
    sys.path.insert(0, TM_SRC)

USER, PASSWORD = "tester", "correct-horse-battery"
SUTS = {"openssh": (2201, "psm-openssh"), "dropbear": (2202, "psm-dropbear"), "gossh": (2203, "psm-gossh"),
        "dropbear2020": (2212, "psm-dropbear2020"), "dropbear2022": (2222, "psm-dropbear2022")}
# Their published learning settings (results/runs/*-v3vm/learn.json): timeout 0.4 s, quiet 0.1 s.
TM_TIMING = {"timeout": 0.4, "quiet": 0.1}


def tm_mapper(sut, strict_kex, **kw):
    from smlearn.ssh.mapper import SSHMapper
    port = SUTS[sut][0]
    opts = dict(TM_TIMING)
    opts.update(kw)
    return SSHMapper("127.0.0.1", port, user=USER, password=PASSWORD, strict_kex=strict_kex, **opts)


def tm_query(m, word, attempts=8):
    """Connection-setup failures (e.g. Dropbear MAX_UNAUTH_PER_IP=5 while other jobs share the server) are
    infrastructure errors, not observations: retry with backoff, as their learner does (reset_with_retry)."""
    import time
    for k in range(attempts):
        try:
            m.reset()
            break
        except (EOFError, OSError):
            if k == attempts - 1:
                raise
            time.sleep(0.2 * 2 ** k)
    return [m.step(i) for i in word]
