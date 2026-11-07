"""Reviewer probe for K1-K4 (KEX-phase disagreements): stock paramiko 5.1.0 (independent client, fresh cookies,
ML-KEM/curve25519 instead of the mapper's DH group14), strict KEX advertised and not advertised.
Reuses rc_probe.py's instrumentation (UNIMPLEMENTED logged with its rejected seq, then hidden from paramiko; 3 s watch).

Modes
  K1 (initial KEX)  k1_dupfresh_before30 / k1_dupfresh_after30: a second KEXINIT with a FRESH cookie, sent right after
                    the server's KEXINIT arrives (before our 30) / right after our 30 (before our NEWKEYS)
                    k1_dupsame_before30: byte-identical copy of our KEXINIT (what P4 makes the mapper send)
  K2 (initial KEX)  k2_sr_before30 / k2_sr_after30: SERVICE_REQUEST ssh-userauth at those points
  K3 (no KEX)       k3_{kex30,newkeys}_{pre,sr,auth}: a stray 30 / 21 after the initial KEX (no SR / after
                    SERVICE_ACCEPT / after auth). Paramiko does NOT switch keys on the stray NEWKEYS, so the
                    continuation (auth, exec id) is a clean test of whether the server really ignored it.
  K4 (post-auth rekey) k4_{dupfresh,sr,ua}_{before30,after30}
If the connection survives: auth (if needed) and exec id on the same connection.
  .venv/bin/python scratch/review/kexp_probe.py openssh=2201:psm-openssh ... --out results/review/kexp_probe.json
"""
import json
import os
import sys
import time
import threading
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rc_probe as rp  # noqa: E402
import paramiko  # noqa: E402
from paramiko.message import Message  # noqa: E402

USER, KEY = rp.USER, rp.KEY


def injector(t, what, rec):
    def f():
        if what == "dupfresh":
            raw = t.local_kex_init
            t._send_message(Message(raw[:1] + os.urandom(16) + raw[17:]))
        elif what == "dupsame":
            t._send_message(Message(t.local_kex_init))
        elif what == "sr":
            t._send_message(rp.msg(5, "ssh-userauth"))
        elif what == "ua":
            t._send_message(rp.msg(50, USER, "ssh-connection", "none"))
        rec["injected_at"] = round(time.time(), 3)
    return f


def patched(t, when, inject):
    out = {}
    for name, cls in type(t)._kex_info.items():
        def make(cls=cls):
            class P(cls):
                def start_kex(self):
                    if when == "before30":
                        inject()
                        cls.start_kex(self)
                    else:
                        cls.start_kex(self)
                        inject()
            P.__name__ = cls.__name__
            return P
        out[name] = make()
    return out


def cont(t, r):
    """Continuation: authenticate if needed, then exec id."""
    if not t.is_active():
        return
    if not t.is_authenticated():
        t.auth_handler = None
        try:
            t.auth_publickey(USER, KEY)
        except Exception as e:
            r["auth_error"] = repr(e)
    r["authenticated"] = t.is_authenticated()
    if t.is_authenticated() and t.is_active():
        rp.exec_id(t, r)


def attempt(port, mode, strict):
    wire = []
    r = {"mode": mode, "strict_kex_advertised": strict}
    sock = rp.socket.create_connection(("127.0.0.1", port), timeout=10)
    t = paramiko.Transport(sock, strict_kex=strict)
    rp.instrument(t, wire)
    parts = mode.split("_")
    try:
        if parts[0] in ("k1", "k2"):
            what, when = parts[1], parts[2]
            t._kex_info = patched(t, when, injector(t, what, r))
            try:
                t.start_client(timeout=6)
                r["initial_kex_completed"] = bool(getattr(t, "initial_kex_done", False))
            except Exception as e:
                r["initial_kex_completed"] = False
                r["start_client_error"] = repr(e)
            r["active_after_watch"] = rp.watch(t, rp.WATCH)
            r["strict_kex_agreed"] = t.agreed_on_strict_kex
            if r["active_after_watch"] and r["initial_kex_completed"]:
                time.sleep(0.3)
                cont(t, r)
            return r
        t.start_client(timeout=6)
        time.sleep(0.5)
        r["strict_kex_agreed"] = t.agreed_on_strict_kex
        if parts[0] == "k3":
            what, ctx = parts[1], parts[2]
            if ctx == "sr":
                ah = rp.SRWaitHandler(t)
                t.auth_handler = ah
                t._send_message(rp.msg(5, "ssh-userauth"))
                r["sr_accepted"] = ah.sr_accepted.wait(3)
                t.auth_handler = None
            elif ctx == "auth":
                t.auth_publickey(USER, KEY)
                r["authenticated_before"] = t.is_authenticated()
                time.sleep(0.5)
            r["injected_at"] = round(time.time(), 3)
            t._send_message(rp.msg(30, os.urandom(32)) if what == "kex30" else rp.msg(21))
            r["active_after_watch"] = rp.watch(t, rp.WATCH)
            cont(t, r)
        elif parts[0] == "k4":
            what, when = parts[1], parts[2]
            t.auth_publickey(USER, KEY)
            r["authenticated_before"] = t.is_authenticated()
            time.sleep(0.5)
            t._kex_info = patched(t, when, injector(t, what, r))
            r["rekey_sent_at"] = round(time.time(), 3)
            r["rekey_completed"] = rp.manual_rekey(t, 4.0)
            r["active_after_watch"] = rp.watch(t, 0.0 if r["rekey_completed"] else 0.5)
            if not r["rekey_completed"] and t.is_active():
                rp.reset_local_kex(t)
                r["local_kex_reset"] = True
            if t.is_active():
                rp.exec_id(t, r)
    except Exception as e:
        r["error"] = repr(e)
    finally:
        r["active_at_end"] = t.is_active()
        t.close()
        r["wire"] = wire
        t0 = r.get("injected_at", r.get("rekey_sent_at", 0))
        r["in_after_injection"] = [
            f"{w['type']}" + (f"(unimpl seq {w['unimpl_seq']})" if "unimpl_seq" in w else "")
            + (f"(disconnect {w['reason']}: {w['desc']})" if "reason" in w else "")
            for w in wire if w["dir"] == "in" and w["t"] >= t0]
        r["disconnect_received"] = [w for w in wire if w["dir"] == "in" and w["type"] == 1]
    return r


MODES = ["k1_dupfresh_before30", "k1_dupfresh_after30", "k1_dupsame_before30", "k2_sr_before30", "k2_sr_after30",
         "k3_kex30_pre", "k3_kex30_sr", "k3_kex30_auth", "k3_newkeys_pre", "k3_newkeys_sr", "k3_newkeys_auth",
         "k4_dupfresh_before30", "k4_dupfresh_after30", "k4_sr_before30", "k4_sr_after30",
         "k4_ua_before30", "k4_ua_after30"]


def main():
    out = sys.argv[sys.argv.index("--out") + 1]
    modes = sys.argv[sys.argv.index("--modes") + 1].split(",") if "--modes" in sys.argv else MODES
    res = {"paramiko": paramiko.__version__, "started": datetime.now(timezone.utc).isoformat(), "targets": {}}
    for tgt in [a for a in sys.argv[1:] if "=" in a and not a.startswith("--")]:
        name, rest = tgt.split("=")
        port, container = rest.split(":")
        res["targets"][name] = []
        for mode in modes:
            for strict in (False, True):
                since = datetime.now(timezone.utc).isoformat()
                a = attempt(int(port), mode, strict)
                time.sleep(0.7)
                a["server_log"] = rp.container_logs(container, since)
                res["targets"][name].append(a)
                print(f"{name:8s} {mode:22s} strict={strict!s:5s} agreed={a.get('strict_kex_agreed')!s:5s} "
                      f"in_after={a['in_after_injection'][:8]} active={a.get('active_after_watch')} "
                      f"kexok={a.get('initial_kex_completed')} rekey={a.get('rekey_completed')} "
                      f"auth={a.get('authenticated')} exec={a.get('exec_output', a.get('exec_error'))!r:.40} "
                      f"err={a.get('error') or a.get('start_client_error') or a.get('auth_error')} "
                      f"log={[l[-90:] for l in a['server_log'] if any(k in l for k in ('protocol_error','xit','nexpected','bogus','strict','isconnect','Premature','handshake error'))][-2:]}",
                      flush=True)
                os.makedirs(os.path.dirname(out), exist_ok=True)
                json.dump(res, open(out, "w"), indent=1)


if __name__ == "__main__":
    main()
