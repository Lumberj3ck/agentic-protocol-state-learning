"""Reviewer probe for the remaining classes C1-C5: an INDEPENDENT client (stock paramiko 5.1.0, no vendored code,
fresh KEXINIT cookies, ML-KEM/curve25519 KEX instead of the mapper's DH group14), run with strict KEX advertised
and not advertised.

Instrumentation: packetizer.read_message / send_message are wrapped (installed BEFORE the handshake) to log every
packet (time, direction, type, sequence number; UNIMPLEMENTED's rejected seq; DISCONNECT reason). Incoming
UNIMPLEMENTED packets are logged and then hidden from paramiko, so that paramiko's own state machine is not
disturbed by them (stock paramiko aborts on an unexpected packet during KEX). After each injected message the
probe watches for 3 s (the mapper reads for 0.35 s), so a late DISCONNECT or close cannot be missed.

Modes:
  C1 rekey_preauth       KEX done, no SERVICE_REQUEST, client sends a fresh KEXINIT (stock _send_kex_init), waits 4 s
     rekey_after_sr      same after SERVICE_ACCEPT
     rekey_postauth      same after publickey auth (control)
     If the rekey does not complete, paramiko's local KEX state is reset, then auth + exec id on the SAME connection.
  C2 ua2_publickey / ua2_password / ua2_none   second USERAUTH_REQUEST after USERAUTH_SUCCESS, then exec id
     ua_pipelined        SR, then two signed publickey requests back to back (second sent before SUCCESS arrives)
  C3 sr_twice            SR, SR (pre-auth), then auth + exec id;  sr_after_auth: auth, SR, then exec id
  C4 kex_newkeys_first   initial KEX: NEWKEYS instead of the KEX init message (30)
     kex_dup_init        initial KEX: the KEX init message (30) sent twice (byte-identical)
     rekey_newkeys_no_kexdh  after auth: rekey where NEWKEYS replaces the KEX init message
  C5 first_kex30 / first_newkeys   a message 30 / 21 sent before the client's KEXINIT (as the very first packet)

  .venv/bin/python scratch/review/rc_probe.py openssh=2201:psm-openssh --reps 2 --out results/review/rc_probe_openssh.json
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
from paramiko.message import Message

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KEY = paramiko.RSAKey.from_private_key_file(os.path.join(ROOT, "keys", "id_rsa"))
USER, PW = "tester", "correct-horse-battery"
WATCH = 3.0


class Cap(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, r):
        self.lines.append(f"{time.time():.3f} {r.levelname} {r.getMessage()}")


class SRWaitHandler(AuthHandler):
    """Records SERVICE_ACCEPT without sending a USERAUTH_REQUEST."""

    def __init__(self, t):
        super().__init__(t)
        self.sr_accepted = threading.Event()
        self.accepts = 0

    def _parse_service_accept(self, m):
        self.accepts += 1
        self.sr_accepted.set()


def instrument(t, wire):
    pk = t.packetizer
    o_read, o_send = pk.read_message, pk.send_message

    def rd():
        while True:
            ptype, m = o_read()
            e = {"t": round(time.time(), 3), "dir": "in", "type": ptype, "seq": getattr(m, "seqno", None)}
            try:
                mm = Message(m.asbytes())
                if ptype == 3:
                    e["unimpl_seq"] = mm.get_int()
                elif ptype == 1:
                    e["reason"] = mm.get_int()
                    e["desc"] = mm.get_text()
                elif ptype == 6:
                    e["service"] = mm.get_text()
            except Exception as ex:  # informative only
                e["decode_error"] = repr(ex)
            wire.append(e)
            if ptype == 3:
                continue  # hide UNIMPLEMENTED from paramiko (logged above)
            return ptype, m

    def sd(data):
        raw = data.asbytes()
        wire.append({"t": round(time.time(), 3), "dir": "out", "type": raw[0],
                     "seq": pk._Packetizer__sequence_number_out})
        return o_send(data)

    pk.read_message, pk.send_message = rd, sd


def watch(t, seconds):
    end = time.time() + seconds
    while time.time() < end and t.is_active():
        time.sleep(0.05)
    return t.is_active()


def exec_id(t, r):
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
        r["exec_output"] = data.decode(errors="replace").strip()
    except Exception as e:
        r["exec_error"] = repr(e)


def msg(ptype, *fields):
    m = Message()
    m.add_byte(bytes([ptype]))
    for f in fields:
        if isinstance(f, bool):
            m.add_boolean(f)
        elif isinstance(f, int):
            m.add_int(f)
        else:
            m.add_string(f)
    return m


def send_pk_request(t):
    """A signed publickey USERAUTH_REQUEST built by stock paramiko's own AuthHandler code."""
    ah = AuthHandler(t)
    ah.auth_event, ah.auth_method, ah.username, ah.private_key = threading.Event(), "publickey", USER, KEY
    t.auth_handler = ah
    fake = Message()
    fake.add_string("ssh-userauth")
    fake.rewind()
    with t.lock:
        ah._parse_service_accept(fake)
    return ah


def manual_rekey(t, wait):
    t.completion_event = threading.Event()
    t._send_kex_init()
    return t.completion_event.wait(wait)


def reset_local_kex(t):
    """After a rekey the server never answered: drop paramiko's half-started local KEX so the session can be used."""
    t.in_kex = False
    t.local_kex_init = None
    t._expected_packet = tuple()
    t.clear_to_send.set()


def patched_kex_info(t, mode, rec):
    out = {}
    for name, cls in type(t)._kex_info.items():
        def make(cls=cls):
            class P(cls):
                def start_kex(self):
                    tr = self.transport
                    if mode == "newkeys_instead":
                        tr._send_message(msg(21))
                        tr._expected_packet = tuple()
                        rec["injected_at"] = round(time.time(), 3)
                    elif mode == "dup_init":
                        orig_send = tr._send_message
                        state = {"dup": False}

                        def dup(m):
                            orig_send(m)
                            raw = m.asbytes()
                            if raw[0] == 30 and not state["dup"]:
                                state["dup"] = True
                                orig_send(Message(raw))
                                rec["injected_at"] = round(time.time(), 3)

                        tr._send_message = dup
                        try:
                            cls.start_kex(self)
                        finally:
                            tr._send_message = orig_send
            P.__name__ = cls.__name__
            return P
        out[name] = make()
    return out


def attempt(port, mode, strict):
    cap = Cap()
    lg = logging.getLogger("paramiko.rc." + mode)
    lg.setLevel(logging.DEBUG)
    lg.addHandler(cap)
    wire = []
    r = {"mode": mode, "strict_kex_advertised": strict}
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    t = paramiko.Transport(sock, strict_kex=strict)
    t.set_log_channel("paramiko.rc." + mode)
    instrument(t, wire)
    try:
        # ---- modes that alter the INITIAL key exchange
        if mode in ("first_kex30", "first_newkeys"):
            orig = t._send_kex_init
            st = {"done": False}

            def first(*a, **k):
                if not st["done"]:
                    st["done"] = True
                    t._send_message(msg(30, os.urandom(32)) if mode == "first_kex30" else msg(21))
                    r["injected_at"] = round(time.time(), 3)
                return orig(*a, **k)

            t._send_kex_init = first
        if mode in ("kex_newkeys_first", "kex_dup_init"):
            t._kex_info = patched_kex_info(t, "newkeys_instead" if mode == "kex_newkeys_first" else "dup_init", r)
        try:
            t.start_client(timeout=6)  # returns silently on timeout
            r["initial_kex_completed"] = bool(getattr(t, "initial_kex_done", False))
        except Exception as e:
            r["initial_kex_completed"] = False
            r["start_client_error"] = repr(e)
        if mode in ("first_kex30", "first_newkeys", "kex_newkeys_first", "kex_dup_init"):
            r["active_after_watch"] = watch(t, WATCH)
            r["strict_kex_agreed"] = t.agreed_on_strict_kex
            if r["active_after_watch"] and r["initial_kex_completed"]:
                time.sleep(0.3)
                try:
                    t.auth_publickey(USER, KEY)
                except Exception as e:
                    r["auth_error"] = repr(e)
                r["authenticated"] = t.is_authenticated()
                if t.is_authenticated():
                    exec_id(t, r)
            return r
        time.sleep(0.5)  # EXT_INFO
        r["strict_kex_agreed"] = t.agreed_on_strict_kex
        r["kex"] = t.kex_engine.__class__.__name__ if t.kex_engine else None

        # ---- C1
        if mode.startswith("rekey"):
            if mode == "rekey_after_sr":
                ah = SRWaitHandler(t)
                t.auth_handler = ah
                t._send_message(msg(5, "ssh-userauth"))
                r["sr_accepted"] = ah.sr_accepted.wait(3)
                t.auth_handler = None
            if mode in ("rekey_postauth", "rekey_newkeys_no_kexdh"):
                t.auth_publickey(USER, KEY)
                r["authenticated_before"] = t.is_authenticated()
                time.sleep(0.5)
            if mode == "rekey_newkeys_no_kexdh":
                t._kex_info = patched_kex_info(t, "newkeys_instead", r)
            r["rekey_sent_at"] = round(time.time(), 3)
            r["rekey_completed"] = manual_rekey(t, 4.0)
            r["active_after_watch"] = watch(t, 0.0 if r["rekey_completed"] else 0.5)
            if not r["rekey_completed"] and t.is_active():
                reset_local_kex(t)
                r["local_kex_reset"] = True
            if t.is_active() and not t.is_authenticated():
                t.auth_handler = None
                try:
                    t.auth_publickey(USER, KEY)
                except Exception as e:
                    r["auth_error"] = repr(e)
            r["authenticated"] = t.is_authenticated()
            if t.is_authenticated() and t.is_active() and mode != "rekey_newkeys_no_kexdh":
                exec_id(t, r)

        # ---- C2
        elif mode.startswith("ua2_"):
            t.auth_publickey(USER, KEY)
            r["authenticated_before"] = t.is_authenticated()
            time.sleep(0.5)  # OpenSSH's hostkeys global request etc.
            r["injected_at"] = round(time.time(), 3)
            if mode == "ua2_publickey":
                send_pk_request(t)
            elif mode == "ua2_password":
                t._send_message(msg(50, USER, "ssh-connection", "password", False, PW))
            else:
                t._send_message(msg(50, USER, "ssh-connection", "none"))
            r["active_after_watch"] = watch(t, WATCH)
            if t.is_active():
                exec_id(t, r)
        elif mode == "ua_pipelined":
            ah = SRWaitHandler(t)
            t.auth_handler = ah
            t._send_message(msg(5, "ssh-userauth"))
            r["sr_accepted"] = ah.sr_accepted.wait(3)
            r["injected_at"] = round(time.time(), 3)
            send_pk_request(t)
            send_pk_request(t)  # second request leaves before the first SUCCESS can arrive
            r["active_after_watch"] = watch(t, WATCH)
            r["authenticated"] = any(w["dir"] == "in" and w["type"] == 52 for w in wire)
            r["success_count"] = sum(1 for w in wire if w["dir"] == "in" and w["type"] == 52)
            if t.is_active():
                exec_id(t, r)

        # ---- C3
        elif mode == "sr_twice":
            ah = SRWaitHandler(t)
            t.auth_handler = ah
            t._send_message(msg(5, "ssh-userauth"))
            r["sr1_accepted"] = ah.sr_accepted.wait(3)
            ah.sr_accepted.clear()
            r["injected_at"] = round(time.time(), 3)
            t._send_message(msg(5, "ssh-userauth"))
            r["sr2_accepted"] = ah.sr_accepted.wait(WATCH)
            r["active_after_watch"] = watch(t, 1.0)
            t.auth_handler = None
            if t.is_active():
                try:
                    t.auth_publickey(USER, KEY)
                except Exception as e:
                    r["auth_error"] = repr(e)
                r["authenticated"] = t.is_authenticated()
                if t.is_authenticated():
                    exec_id(t, r)
        elif mode == "sr_after_auth":
            t.auth_publickey(USER, KEY)
            r["authenticated_before"] = t.is_authenticated()
            time.sleep(0.5)
            r["injected_at"] = round(time.time(), 3)
            t._send_message(msg(5, "ssh-userauth"))
            r["active_after_watch"] = watch(t, WATCH)
            if t.is_active():
                exec_id(t, r)
    except Exception as e:
        r["error"] = repr(e)
    finally:
        r["active_at_end"] = t.is_active()
        t.close()
        lg.removeHandler(cap)
        r["wire"] = wire
        t0 = r.get("injected_at", r.get("rekey_sent_at", 0))
        r["in_after_injection"] = [
            f"{w['type']}" + (f"(unimpl seq {w['unimpl_seq']})" if "unimpl_seq" in w else "")
            + (f"(disconnect {w['reason']}: {w['desc']})" if "reason" in w else "")
            for w in wire if w["dir"] == "in" and w["t"] >= t0]
        r["disconnect_received"] = [w for w in wire if w["dir"] == "in" and w["type"] == 1]
        keep = ("Disconnect", "EOF", "Oops", "unhandled", "Authentication", "uthenticat", "Exception", "Error",
                "error", "strict", "Strict", "Kex:", "Rekey", "rekey", "Switch", "Secsh")
        r["log"] = [ln for ln in cap.lines if any(k in ln for k in keep)][-40:]
    return r


def container_logs(name, since):
    p = subprocess.run(["docker", "logs", "-t", "--since", since, name], capture_output=True, text=True, timeout=30)
    lines = (p.stdout + p.stderr).splitlines()
    keep = ("dispatch_protocol", "kex_protocol_error", "strict", "KEXINIT", "isconnect", "send packet: type 1 ",
            "Unexpected", "unexpected", "Exit", "handshake", "First packet", "first packet", "Received message",
            "closed", "Integrity", "newkeys", "Premature", "Accepted", "auth succeeded", "bogus", "rror", "service")
    return [ln for ln in lines if any(k in ln for k in keep)][-150:]


MODES = ["rekey_preauth", "rekey_after_sr", "rekey_postauth",
         "ua2_publickey", "ua2_password", "ua2_none", "ua_pipelined",
         "sr_twice", "sr_after_auth",
         "kex_newkeys_first", "kex_dup_init", "rekey_newkeys_no_kexdh",
         "first_kex30", "first_newkeys"]


def main():
    out = sys.argv[sys.argv.index("--out") + 1]
    reps = int(sys.argv[sys.argv.index("--reps") + 1]) if "--reps" in sys.argv else 1
    modes = sys.argv[sys.argv.index("--modes") + 1].split(",") if "--modes" in sys.argv else MODES
    res = {"paramiko": paramiko.__version__, "started": datetime.now(timezone.utc).isoformat(), "watch_s": WATCH,
           "targets": {}}
    for tgt in [a for a in sys.argv[1:] if "=" in a and not a.startswith("--")]:
        name, rest = tgt.split("=")
        port, container = rest.split(":")
        res["targets"][name] = []
        for mode in modes:
            for strict in (False, True):
                for _ in range(reps):
                    since = datetime.now(timezone.utc).isoformat()
                    a = attempt(int(port), mode, strict)
                    time.sleep(0.7)
                    a["server_log"] = container_logs(container, since)
                    res["targets"][name].append(a)
                    print(f"{name:8s} {mode:22s} strict={strict!s:5s} agreed={a.get('strict_kex_agreed')!s:5s} "
                          f"in_after={a['in_after_injection'][:8]} active={a.get('active_after_watch')} "
                          f"kexok={a.get('initial_kex_completed')} rekey={a.get('rekey_completed')} "
                          f"auth={a.get('authenticated')} exec={a.get('exec_output', a.get('exec_error'))!r:.60} "
                          f"err={a.get('error') or a.get('start_client_error') or a.get('auth_error')}", flush=True)
                    os.makedirs(os.path.dirname(out), exist_ok=True)
                    json.dump(res, open(out, "w"), indent=1)


if __name__ == "__main__":
    main()
