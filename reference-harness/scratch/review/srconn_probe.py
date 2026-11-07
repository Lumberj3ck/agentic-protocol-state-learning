"""Reviewer probe for E1/E2 (SERVICE_REQUEST "ssh-connection" before / after authentication) with an INDEPENDENT
client: stock paramiko 5.1.0, fresh cookies, ML-KEM/curve25519 KEX, strict KEX advertised and not advertised.
Reuses the instrumentation of rc_probe.py (every packet logged with type/seq; UNIMPLEMENTED's rejected seq;
DISCONNECT reason code and text; UNIMPLEMENTED hidden from paramiko). After each injection the probe watches 3 s.

Modes:
  srconn_preauth          KEX done, no SERVICE_REQUEST, send SERVICE_REQUEST "ssh-connection"
  srconn_after_sr         SERVICE_REQUEST "ssh-userauth" accepted, then "ssh-connection"
  srbogus_preauth         control: SERVICE_REQUEST "bogus-service@example.com" right after KEX
  srconn_postauth         publickey auth, then "ssh-connection"; then exec id on the same connection
  srconn_postauth_chan    publickey auth, exec id (channel 0), then "ssh-connection", then exec id again
  After auth, paramiko's AuthHandler._parse_service_accept is replaced by a recorder, so a SERVICE_ACCEPT does
  NOT make paramiko send another USERAUTH_REQUEST (checked in the wire log: no outgoing 50 after injection).

  ./gx .venv/bin/python scratch/review/srconn_probe.py openssh=2201:psm-openssh dropbear=2202:psm-dropbear \
       gossh=2203:psm-gossh --reps 2 --out results/review/srconn_probe.json
"""
import json
import logging
import os
import socket
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paramiko  # noqa: E402
from rc_probe import KEY, USER, WATCH, Cap, SRWaitHandler, container_logs, exec_id, instrument, msg, watch  # noqa: E402

MODES = ["srconn_preauth", "srconn_after_sr", "srbogus_preauth", "srconn_postauth", "srconn_postauth_chan"]


def attempt(port, mode, strict):
    cap = Cap()
    lg = logging.getLogger("paramiko.srconn." + mode)
    lg.setLevel(logging.DEBUG)
    lg.addHandler(cap)
    wire = []
    r = {"mode": mode, "strict_kex_advertised": strict}
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    t = paramiko.Transport(sock, strict_kex=strict)
    t.set_log_channel("paramiko.srconn." + mode)
    instrument(t, wire)
    try:
        t.start_client(timeout=6)
        time.sleep(0.5)  # EXT_INFO
        r["strict_kex_agreed"] = t.agreed_on_strict_kex
        r["kex"] = t.kex_engine.__class__.__name__ if t.kex_engine else None
        if mode in ("srconn_preauth", "srconn_after_sr", "srbogus_preauth"):
            ah = SRWaitHandler(t)
            t.auth_handler = ah
            if mode == "srconn_after_sr":
                t._send_message(msg(5, "ssh-userauth"))
                r["sr_auth_accepted"] = ah.sr_accepted.wait(3)
                ah.sr_accepted.clear()
            r["injected_at"] = round(time.time(), 3)
            t._send_message(msg(5, "bogus-service@example.com" if mode == "srbogus_preauth" else "ssh-connection"))
            r["sr_accepted"] = ah.sr_accepted.wait(WATCH)
            r["active_after_watch"] = watch(t, 0.0 if not r["sr_accepted"] else 1.0)
        else:
            t.auth_publickey(USER, KEY)
            r["authenticated_before"] = t.is_authenticated()
            time.sleep(0.5)  # OpenSSH's hostkeys GLOBAL_REQUEST etc.
            if mode == "srconn_postauth_chan":
                pre = {}
                exec_id(t, pre)
                r["exec_before"] = pre.get("exec_output", pre.get("exec_error"))
            accepts = []
            t.auth_handler._parse_service_accept = lambda m: accepts.append(m.get_text())
            r["injected_at"] = round(time.time(), 3)
            t._send_message(msg(5, "ssh-connection"))
            r["active_after_watch"] = watch(t, WATCH)
            r["service_accepts_after_injection"] = accepts
            if t.is_active():
                exec_id(t, r)
    except Exception as e:
        r["error"] = repr(e)
    finally:
        r["active_at_end"] = t.is_active()
        t.close()
        lg.removeHandler(cap)
        r["wire"] = wire
        t0 = r.get("injected_at", 0)
        r["in_after_injection"] = [
            f"{w['type']}" + (f"(unimpl seq {w['unimpl_seq']})" if "unimpl_seq" in w else "")
            + (f"(disconnect {w['reason']}: {w['desc']})" if "reason" in w else "")
            + (f"(accept {w['service']})" if "service" in w else "")
            for w in wire if w["dir"] == "in" and w["t"] >= t0]
        r["out_after_injection"] = [f"{w['type']}(seq {w['seq']})" for w in wire if w["dir"] == "out" and w["t"] >= t0]
        r["disconnect_received"] = [w for w in wire if w["dir"] == "in" and w["type"] == 1]
        keep = ("Disconnect", "EOF", "Oops", "unhandled", "uthenticat", "Exception", "Error", "error", "strict",
                "Strict", "Kex:", "Secsh", "service", "Service")
        r["log"] = [ln for ln in cap.lines if any(k in ln for k in keep)][-40:]
    return r


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
                          f"in_after={a['in_after_injection'][:8]} out_after={a['out_after_injection'][:6]} "
                          f"active={a.get('active_after_watch')} acc={a.get('sr_accepted', a.get('service_accepts_after_injection'))} "
                          f"exec={a.get('exec_output', a.get('exec_error'))!r:.50} err={a.get('error')}", flush=True)
                    os.makedirs(os.path.dirname(out), exist_ok=True)
                    json.dump(res, open(out, "w"), indent=1)


if __name__ == "__main__":
    main()
