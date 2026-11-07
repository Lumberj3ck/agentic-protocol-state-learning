"""Reviewer probe for D2 (questions 2-3): an INDEPENDENT client (stock paramiko, no vendored code) that sends
connection-protocol messages (>= 80) BEFORE authentication and records, at the packet level, what comes back.

Instrumentation: the stock packetizer's read_message / send_message are wrapped to log (time, direction, type,
sequence number, and for UNIMPLEMENTED / DISCONNECT / channel replies the decoded fields). paramiko's own log shows
"Disconnect (code N)" if the server sends SSH_MSG_DISCONNECT, "EOF in transport thread" if it just closes TCP.

Modes (each on a fresh connection after a normal paramiko key exchange):
  ch_open            CHANNEL_OPEN "session" (sender channel 7), no SERVICE_REQUEST
  sr_ch_open         SERVICE_REQUEST ssh-userauth, wait SERVICE_ACCEPT, then CHANNEL_OPEN
  global_req         GLOBAL_REQUEST "tcpip-forward" want_reply=1 (message 80), no SERVICE_REQUEST
  ch_open_then_auth  CHANNEL_OPEN (chan 7); 1 s; normal SR + publickey auth; 1.5 s watching for any late reply to
                     chan 7; then open_session + exec id (proves the connection is still usable and clean)
  many_then_auth     CH_OPEN x3, GLOBAL_REQUEST, CHANNEL_REQUEST(98, chan 0), CHANNEL_DATA(94, chan 0), wait 10 s,
                     then auth + exec id (does the server disconnect later or after repeated >= 80 messages?)
  grace_ch_open / grace_idle   (only with --grace) CH_OPEN or nothing, then wait up to 140 s for the server to close
                     (OpenSSH LoginGraceTime defaults to 120 s): is any later close caused by the CH_OPEN?

  .venv/bin/python scratch/review/ch_open_probe.py openssh=2201:psm-openssh ... --reps 2 --out results/review/ch_open_probe.json
"""
import json
import logging
import os
import socket
import struct
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


class Cap(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, r):
        self.lines.append(f"{time.time():.3f} {r.levelname} {r.getMessage()}")


class SRWaitHandler(AuthHandler):
    """Records SERVICE_ACCEPT without sending a USERAUTH_REQUEST (stock _parse_service_accept would send one)."""

    def __init__(self, t):
        super().__init__(t)
        self.sr_accepted = threading.Event()

    def _parse_service_accept(self, m):
        self.sr_accepted.set()


def instrument(t, wire):
    pk = t.packetizer
    o_read, o_send = pk.read_message, pk.send_message

    def rd():
        ptype, m = o_read()
        e = {"t": round(time.time(), 3), "dir": "in", "type": ptype, "seq": m.seqno}
        raw = m.asbytes()
        try:
            mm = Message(raw)
            if ptype == 3:
                e["unimpl_seq"] = mm.get_int()
            elif ptype == 1:
                e["reason"] = mm.get_int()
                e["desc"] = mm.get_text()
            elif ptype in (91, 92):
                e["recipient_channel"] = mm.get_int()
            elif ptype == 80:
                e["request"] = mm.get_text()
        except Exception as ex:  # decoding is informative only
            e["decode_error"] = repr(ex)
        wire.append(e)
        return ptype, m

    def sd(data):
        raw = data.asbytes()
        wire.append({"t": round(time.time(), 3), "dir": "out", "type": raw[0],
                     "seq": pk._Packetizer__sequence_number_out})
        return o_send(data)

    pk.read_message, pk.send_message = rd, sd


def msg_ch_open(chan):
    m = Message()
    m.add_byte(bytes([90]))
    m.add_string("session")
    m.add_int(chan)
    m.add_int(2097152)
    m.add_int(32768)
    return m


def msg_global_req():
    m = Message()
    m.add_byte(bytes([80]))
    m.add_string("tcpip-forward")
    m.add_boolean(True)
    m.add_string("127.0.0.1")
    m.add_int(0)
    return m


def msg_ch_req(chan):
    m = Message()
    m.add_byte(bytes([98]))
    m.add_int(chan)
    m.add_string("exec")
    m.add_boolean(True)
    m.add_string("id")
    return m


def msg_ch_data(chan):
    m = Message()
    m.add_byte(bytes([94]))
    m.add_int(chan)
    m.add_string(b"hello")
    return m


def watch(t, seconds):
    end = time.time() + seconds
    while time.time() < end and t.is_active():
        time.sleep(0.05)
    return t.is_active()


def exec_id(t, r):
    try:
        ch = t.open_session(timeout=5)
        r["post_channel_id"] = ch.get_id()
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
    except Exception as e:
        r["exec_error"] = repr(e)


def attempt(port, mode, grace_wait=140):
    cap = Cap()
    lg = logging.getLogger("paramiko.probe." + mode)
    lg.setLevel(logging.DEBUG)
    lg.addHandler(cap)
    wire = []
    r = {"mode": mode}
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    r["local_port"] = sock.getsockname()[1]
    t = paramiko.Transport(sock)
    t.set_log_channel("paramiko.probe." + mode)
    try:
        t.start_client(timeout=10)
        instrument(t, wire)
        time.sleep(0.5)  # EXT_INFO
        r["strict_kex_agreed"] = t.agreed_on_strict_kex
        r["kex"] = t.kex_engine.__class__.__name__
        t0 = time.time()
        r["t_probe_start"] = round(t0, 3)
        if mode == "sr_ch_open":
            ah = SRWaitHandler(t)
            t.auth_handler = ah
            m = Message()
            m.add_byte(bytes([5]))
            m.add_string("ssh-userauth")
            t._send_user_message(m)
            r["sr_accepted"] = ah.sr_accepted.wait(3)
        if mode in ("ch_open", "sr_ch_open", "ch_open_then_auth", "grace_ch_open"):
            t._send_user_message(msg_ch_open(7))
        elif mode == "global_req":
            t._send_user_message(msg_global_req())
        elif mode == "many_then_auth":
            for c in (7, 8, 9):
                t._send_user_message(msg_ch_open(c))
            t._send_user_message(msg_global_req())
            t._send_user_message(msg_ch_req(0))
            t._send_user_message(msg_ch_data(0))
        if mode.startswith("grace"):
            alive = watch(t, grace_wait)
            r["closed_after_s"] = None if alive else round(time.time() - t0, 1)
        else:
            alive = watch(t, 10.0 if mode == "many_then_auth" else 3.0)
        r["active_after_probe"] = alive
        if mode in ("ch_open_then_auth", "many_then_auth") and alive:
            t.auth_handler = None
            try:
                t.auth_publickey("tester", KEY)
            except Exception as e:
                r["auth_error"] = repr(e)
            r["authenticated"] = t.is_authenticated()
            time.sleep(1.5)  # any late open-confirmation / failure for the pre-auth channel ids would arrive here
            if t.is_authenticated():
                exec_id(t, r)
    except Exception as e:
        r["error"] = repr(e)
    finally:
        r["active_at_end"] = t.is_active()
        t.close()
        lg.removeHandler(cap)
    r["wire"] = wire
    r["late_replies_for_preauth_channels"] = [w for w in wire if w.get("recipient_channel") in (7, 8, 9)]
    r["disconnect_received"] = [w for w in wire if w["dir"] == "in" and w["type"] == 1]
    keep = ("Disconnect", "EOF", "Oops", "unhandled", "Authentication", "userauth", "Exception", "Error", "error",
            "channel", "Channel", "Secsh", "strict")
    r["log"] = [ln for ln in cap.lines if any(k in ln for k in keep)][-40:]
    return r


def container_logs(name, since):
    p = subprocess.run(["docker", "logs", "-t", "--since", since, name], capture_output=True, text=True, timeout=30)
    lines = (p.stdout + p.stderr).splitlines()
    keep = ("type 90", "type 80", "type 94", "type 98", "dispatch", "send packet: type 3", "send packet: type 1 ",
            "Accepted", "Connection closed", "Disconnect", "isconnect", "Received message", "handshake", "Exit",
            "Child", "rror", "closed", "grace", "Timeout", "unexpected", "session_new", "channel")
    return [ln for ln in lines if any(k in ln for k in keep)][-150:]


def main():
    out = sys.argv[sys.argv.index("--out") + 1]
    reps = int(sys.argv[sys.argv.index("--reps") + 1]) if "--reps" in sys.argv else 1
    grace = "--grace" in sys.argv
    modes = ["grace_ch_open", "grace_idle"] if grace else \
        ["ch_open", "sr_ch_open", "global_req", "ch_open_then_auth", "many_then_auth"]
    res = {"paramiko": paramiko.__version__, "started": datetime.now(timezone.utc).isoformat(), "targets": {}}
    for tgt in [a for a in sys.argv[1:] if "=" in a]:
        name, rest = tgt.split("=")
        port, container = rest.split(":")
        res["targets"][name] = []
        if grace:  # both grace connections in parallel, then read the log once
            since = datetime.now(timezone.utc).isoformat()
            out_r = {}
            ths = [threading.Thread(target=lambda md=md: out_r.__setitem__(md, attempt(int(port), md))) for md in modes]
            [th.start() for th in ths]
            [th.join() for th in ths]
            time.sleep(1)
            logs = container_logs(container, since)
            for md in modes:
                out_r[md]["server_log"] = logs
                res["targets"][name].append(out_r[md])
                print(name, md, "closed_after_s", out_r[md].get("closed_after_s"),
                      "disc", out_r[md]["disconnect_received"])
            continue
        for mode in modes:
            for _ in range(reps):
                since = datetime.now(timezone.utc).isoformat()
                a = attempt(int(port), mode)
                time.sleep(0.5)
                a["server_log"] = container_logs(container, since)
                res["targets"][name].append(a)
                ins = [f"{w['type']}" + (f"(seq{w['unimpl_seq']})" if "unimpl_seq" in w else "") +
                       (f"(ch{w['recipient_channel']})" if "recipient_channel" in w else "")
                       for w in a["wire"] if w["dir"] == "in" and w["t"] >= a.get("t_probe_start", 0)]
                print(f"{name:9s} {mode:18s} in_after_probe={ins} active={a['active_after_probe'] if 'active_after_probe' in a else None} "
                      f"auth={a.get('authenticated')} exec={a.get('exec_id_output', a.get('exec_error'))!r} "
                      f"disc={a['disconnect_received']} late={a['late_replies_for_preauth_channels']} err={a.get('error')}")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(res, open(out, "w"), indent=1)


if __name__ == "__main__":
    main()
