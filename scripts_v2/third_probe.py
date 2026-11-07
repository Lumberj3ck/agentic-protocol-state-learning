"""Third, independent client for the auto-KEXINIT disagreement classes: stock paramiko 5.1.0 Packetizer (framing only,
no paramiko KEX/auth state machine) on a raw socket, so we can send EXACTLY the message order of either harness:
  theirs: X [Y ...]                (no client KEXINIT unless the input says so)
  ours:   X, KEXINIT, [Y ...]      (the ssh-fuzzer mapper's automatic KEXINIT after the first non-KEXINIT input)
Unencrypted phase only (no NEWKEYS is ever completed), so no key derivation is needed. Every received packet type
and the time of the TCP close are logged, plus the server container's log.
  .venv-tm/bin/python scripts_v2/third_probe.py --reps 3 --out results/v2/A/third_probe.json"""
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

import paramiko
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from paramiko.message import Message
from paramiko.packet import Packetizer

SUTS = {"openssh": (2201, "psm-openssh"), "dropbear": (2202, "psm-dropbear"), "gossh": (2203, "psm-gossh")}
WIN = 1.0


def kexinit():
    m = Message()
    m.add_byte(bytes([20]))
    m.add_bytes(os.urandom(16))
    for v in ("curve25519-sha256,curve25519-sha256@libssh.org", "ssh-ed25519,rsa-sha2-256",
              "aes128-ctr", "aes128-ctr", "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", ""):
        m.add_string(v)
    m.add_boolean(False)
    m.add_int(0)
    return m


def build(sym):
    m = Message()
    if sym == "KEXINIT":
        return kexinit()
    if sym == "KEX30":
        m.add_byte(bytes([30]))
        m.add_string(X25519PrivateKey.generate().public_key().public_bytes_raw())
    elif sym == "NEWKEYS":
        m.add_byte(bytes([21]))
    elif sym == "SR_AUTH":
        m.add_byte(bytes([5]))
        m.add_string("ssh-userauth")
    return m


def collect(pk, sock, t0, until):
    got = []
    while time.time() < until:
        sock.settimeout(max(0.01, until - time.time()))
        try:
            ptype, _ = pk.read_message()
            got.append({"t": round(time.time() - t0, 3), "type": ptype})
        except (socket.timeout, paramiko.ssh_exception.SSHException) as e:
            if isinstance(e, socket.timeout) or "timeout" in repr(e).lower():
                break
            got.append({"t": round(time.time() - t0, 3), "closed": repr(e)})
            return got, True
        except (EOFError, OSError) as e:
            got.append({"t": round(time.time() - t0, 3), "closed": repr(e)})
            return got, True
    return got, False


def attempt(port, word):
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    t0 = time.time()
    sock.sendall(b"SSH-2.0-psm_third_probe\r\n")
    buf = b""
    while b"\n" not in buf:
        buf += sock.recv(1)
    pk = Packetizer(sock)
    pk.set_inbound_cipher  # stock framing, no cipher installed: plaintext phase
    ptype, _ = pk.read_message()  # server KEXINIT
    steps = [{"recv_before_first_input": ptype}]
    closed = False
    for sym in word:
        rec = {"sent": sym, "t": round(time.time() - t0, 3)}
        if closed:
            rec["result"] = "already closed"
            steps.append(rec)
            continue
        try:
            pk.send_message(build(sym))
        except (OSError, EOFError) as e:
            rec["send_error"] = repr(e)
            closed = True
            steps.append(rec)
            continue
        got, closed = collect(pk, sock, t0, time.time() + WIN)
        rec["received"] = got
        steps.append(rec)
    if not closed:
        got, closed = collect(pk, sock, t0, time.time() + 2.0)
        steps.append({"final_watch": got})
    sock.close()
    return {"steps": steps, "closed_at_end": closed}


# (class id, sut, theirs word, ours word)
CASES = [
    ("M2-go-first-msg", "gossh", ["KEX30"], ["KEX30", "KEXINIT"]),
    ("M2-go-first-msg", "gossh", ["NEWKEYS"], ["NEWKEYS", "KEXINIT"]),
    ("M2-go-first-msg", "gossh", ["SR_AUTH"], ["SR_AUTH", "KEXINIT"]),
    ("M2-dropbear-first-sr", "dropbear", ["SR_AUTH"], ["SR_AUTH", "KEXINIT"]),
    ("M1-kex30-kex30", "openssh", ["KEX30", "KEX30"], ["KEX30", "KEXINIT", "KEX30"]),
    ("M1-kex30-kex30", "dropbear", ["KEX30", "KEX30"], ["KEX30", "KEXINIT", "KEX30"]),
    ("M1-kex30-kexinit", "openssh", ["KEX30", "KEXINIT"], ["KEX30", "KEXINIT", "KEXINIT"]),
    ("M1-kex30-kexinit", "dropbear", ["KEX30", "KEXINIT"], ["KEX30", "KEXINIT", "KEXINIT"]),
]


def logs(container, since):
    p = subprocess.run(["docker", "logs", "-t", "--since", since, container], capture_output=True, text=True, timeout=30)
    return (p.stdout + p.stderr).splitlines()[-40:]


def main():
    out = sys.argv[sys.argv.index("--out") + 1]
    reps = int(sys.argv[sys.argv.index("--reps") + 1])
    res = {"paramiko": paramiko.__version__, "started": datetime.now(timezone.utc).isoformat(), "window_s": WIN, "cases": []}
    for cid, sut, theirs, ours in CASES:
        port, cont = SUTS[sut]
        for label, word in (("theirs-order", theirs), ("ours-order", ours)):
            since = datetime.now(timezone.utc).isoformat()
            runs = [attempt(port, word) for _ in range(reps)]
            time.sleep(0.5)
            summ = [[(s.get("sent"), [g.get("type", "CLOSE") for g in s.get("received", s.get("final_watch", []))]) for s in r["steps"][1:]] for r in runs]
            res["cases"].append({"class": cid, "sut": sut, "order": label, "word": word, "runs": runs,
                                 "summary": summ[0], "deterministic": all(x == summ[0] for x in summ),
                                 "server_log": logs(cont, since)})
            print(cid, sut, label, word, summ[0], "" if all(x == summ[0] for x in summ) else "NONDET", flush=True)
    json.dump(res, open(out, "w"), indent=1)


if __name__ == "__main__":
    main()
