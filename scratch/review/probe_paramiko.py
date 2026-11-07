"""Reviewer probe (hypotheses 1, 2, 5): an INDEPENDENT client (stock paramiko, no vendored code) that sends a
publickey USERAUTH_REQUEST with or without a prior SERVICE_REQUEST "ssh-userauth".

The request is built by stock paramiko's own AuthHandler._parse_service_accept (the exact code path a normal
paramiko login uses after SERVICE_ACCEPT); in mode no_sr we just never send the SERVICE_REQUEST.
If the server authenticates, we open a session channel and exec `id` to prove the session is really usable.
paramiko's DEBUG log shows whether the peer sent DISCONNECT ("Disconnect (code N)") or just closed ("EOF").

Modes: sr (control), no_sr, no_sr_then_sr (after the no-SR attempt, do a normal SR+auth on the same connection).
  .venv/bin/python scratch/review/probe_paramiko.py openssh=2201:psm-openssh ... --out results/review/probe_paramiko.json
"""
import json
import logging
import os
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

import paramiko
from paramiko.auth_handler import AuthHandler

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KEY = paramiko.RSAKey.from_private_key_file(os.path.join(ROOT, "keys", "id_rsa"))


class Cap(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, r):
        self.lines.append(f"{r.relativeCreated/1000:8.3f} {r.levelname} {r.getMessage()}")


KEEP = ("Disconnect", "EOF", "Oops", "unhandled", "uthentication", "userauth", "Auth", "MAC", "strict", "kex algos",
        "Kex", "server-sig-algs", "extension", "Received", "channel", "Channel", "Unknown", "Socket", "exception",
        "Exception", "Error", "error")


def attempt(port, mode, strict):
    cap = Cap()
    lg = logging.getLogger("paramiko")
    lg.setLevel(logging.DEBUG)
    lg.addHandler(cap)
    r = {"mode": mode, "strict_kex_advertised": strict}
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    t = paramiko.Transport(sock, strict_kex=strict)
    try:
        t.start_client(timeout=10)
        time.sleep(0.5)  # let EXT_INFO (server-sig-algs) be processed before choosing the RSA signature algorithm
        r["remote_version"] = t.remote_version
        r["strict_kex_agreed"] = t.agreed_on_strict_kex
        r["kex"] = t.kex_engine.__class__.__name__
        r["server_sig_algs"] = (t.server_extensions or {}).get("server-sig-algs", b"").decode()[:200]
        ev = threading.Event()
        ah = AuthHandler(t)
        ah.auth_event, ah.auth_method, ah.username, ah.private_key = ev, "publickey", "tester", KEY
        t.auth_handler = ah
        if mode == "sr":
            with t.lock:
                ah._request_auth()  # SERVICE_REQUEST; SERVICE_ACCEPT then triggers the same _parse_service_accept
        else:
            fake = paramiko.Message()
            fake.add_string("ssh-userauth")
            fake.rewind()
            with t.lock:
                ah._parse_service_accept(fake)  # sends USERAUTH_REQUEST directly, no SERVICE_REQUEST on the wire
        ev.wait(5)
        time.sleep(1.0)  # catch anything late (UNIMPL, DISCONNECT, EOF)
        r["first_attempt"] = {"event_set": ev.is_set(), "authenticated": t.is_authenticated(), "active": t.is_active(),
                              "exception": repr(t.get_exception())}
        if mode == "no_sr_then_sr" and t.is_active() and not t.is_authenticated():
            try:
                t.auth_publickey("tester", KEY)
            except Exception as e:  # recorded, not fatal
                r["second_attempt_error"] = repr(e)
            r["second_attempt"] = {"authenticated": t.is_authenticated(), "active": t.is_active()}
        if t.is_authenticated():
            try:
                ch = t.open_session(timeout=5)
                ch.settimeout(5)
                ch.exec_command("id")
                data = b""
                end = time.time() + 5
                while time.time() < end:
                    try:
                        d = ch.recv(4096)
                    except socket.timeout:
                        break
                    if not d:
                        break
                    data += d
                r["exec_id_output"] = data.decode(errors="replace").strip()
                r["exec_exit_status"] = ch.recv_exit_status() if ch.exit_status_ready() else None
            except Exception as e:
                r["exec_error"] = repr(e)
    except Exception as e:
        r["error"] = repr(e)
    finally:
        r["active_at_end"] = t.is_active()
        t.close()
        lg.removeHandler(cap)
    r["log"] = [ln for ln in cap.lines if any(k in ln for k in KEEP)][-60:]
    return r


def container_logs(name, since):
    p = subprocess.run(["docker", "logs", "--since", since, name], capture_output=True, text=True, timeout=30)
    lines = (p.stdout + p.stderr).splitlines()
    keep = ("type 50", "dispatch", "send packet: type 3", "Accepted", "Connection closed", "Disconnect", "auth",
            "Auth", "handshake", "Exit", "Child", "error", "closed", "session", "userauth", "service")
    return [ln for ln in lines if any(k in ln for k in keep)][-120:]


def main():
    out = sys.argv[sys.argv.index("--out") + 1]
    reps = int(sys.argv[sys.argv.index("--reps") + 1]) if "--reps" in sys.argv else 1
    res = {"paramiko": paramiko.__version__, "started": datetime.now(timezone.utc).isoformat(), "targets": {}}
    for tgt in [a for a in sys.argv[1:] if "=" in a]:
        name, rest = tgt.split("=")
        port, container = rest.split(":")
        res["targets"][name] = []
        for strict in (False, True):
            for mode in ("sr", "no_sr", "no_sr_then_sr"):
                for _ in range(reps):
                    since = datetime.now(timezone.utc).isoformat()
                    a = attempt(int(port), mode, strict)
                    time.sleep(0.5)
                    a["server_log"] = container_logs(container, since)
                    res["targets"][name].append(a)
                    fa = a.get("first_attempt", {})
                    print(f"{name:9s} strict={strict!s:5s} {mode:14s} auth1={fa.get('authenticated')} "
                          f"active1={fa.get('active')} auth2={a.get('second_attempt')} exec={a.get('exec_id_output', a.get('exec_error'))!r} "
                          f"err={a.get('error')}")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(res, open(out, "w"), indent=1)


if __name__ == "__main__":
    main()
