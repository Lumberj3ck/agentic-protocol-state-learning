"""Third client (stock paramiko 5.1.0 Transport + raw Message sends) for the harness disagreements that need an
encrypted session: our NEWKEYS taint (T1, T2) and our CH_MAX limit (T3, T4).
Reuses the v1 reviewer instrumentation (scratch/review/rc_probe.py, imported unchanged): every packet logged,
incoming UNIMPLEMENTED logged and hidden from paramiko, 3 s watch.
  T1 prerekey_nk_30     pre-auth rekey: after the server KEXINIT send NEWKEYS, wait, then the real 30 (= their
                        KEXINIT KEX30 NEWKEYS KEXINIT NEWKEYS KEX30); does the rekey complete, then auth + exec id?
  T2 prerekey_nk_nk     same with NEWKEYS, NEWKEYS, then 30
  T3 two_channels       auth, then two session channels (our mapper refuses the 2nd as CH_MAX)
  T4 chopen_in_rekey    auth, channel, then a rekey with CHANNEL_OPEN sent after the server KEXINIT, before 30
  .venv-tm/bin/python scripts_v2/third_probe2.py --reps 3 --out results/v2/A/third_probe2.json"""
import json
import os
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scratch", "review"))
import rc_probe as rp  # noqa: E402
import paramiko  # noqa: E402

SUTS = {"openssh": (2201, "psm-openssh"), "dropbear": (2202, "psm-dropbear"), "gossh": (2203, "psm-gossh")}


def patched(t, before30, rec):
    out = {}
    for name, cls in type(t)._kex_info.items():
        def make(cls=cls):
            class P(cls):
                def start_kex(self):
                    before30(self.transport)
                    rec["injected_at"] = rec.get("injected_at", round(time.time(), 3))
                    time.sleep(0.7)
                    cls.start_kex(self)
            P.__name__ = cls.__name__
            return P
        out[name] = make()
    return out


def attempt(port, mode):
    wire = []
    r = {"mode": mode}
    sock = rp.socket.create_connection(("127.0.0.1", port), timeout=10)
    t = paramiko.Transport(sock, strict_kex=False)
    rp.instrument(t, wire)
    try:
        t.start_client(timeout=6)
        time.sleep(0.5)
        if mode in ("prerekey_nk_30", "prerekey_nk_nk"):
            n = 1 if mode == "prerekey_nk_30" else 2
            t._kex_info = patched(t, lambda tr: [tr._send_message(rp.msg(21)) for _ in range(n)], r)
            r["rekey_completed"] = rp.manual_rekey(t, 6.0)
            r["active_after_watch"] = rp.watch(t, 1.0)
            if t.is_active():
                t.auth_handler = None
                try:
                    t.auth_publickey(rp.USER, rp.KEY)
                except Exception as e:
                    r["auth_error"] = repr(e)
                r["authenticated"] = t.is_authenticated()
                if t.is_authenticated():
                    rp.exec_id(t, r)
        elif mode == "two_channels":
            t.auth_publickey(rp.USER, rp.KEY)
            r["injected_at"] = round(time.time(), 3)
            chans = []
            for k in range(2):
                try:
                    chans.append(t.open_session(timeout=5))
                    r[f"channel{k + 1}_opened"] = True
                except Exception as e:
                    r[f"channel{k + 1}_opened"] = repr(e)
            if len(chans) == 2:
                chans[1].exec_command("id")
                r["exec_on_channel2"] = chans[1].recv(200).decode(errors="replace").strip()
        elif mode == "chopen_in_rekey":
            t.auth_publickey(rp.USER, rp.KEY)
            t.open_session(timeout=5)
            time.sleep(0.3)
            t._kex_info = patched(t, lambda tr: tr._send_message(rp.msg(90, "session", 7, 2 ** 21, 32768)), r)
            r["rekey_completed"] = rp.manual_rekey(t, 4.0)
            r["active_after_watch"] = rp.watch(t, rp.WATCH)
    except Exception as e:
        r["error"] = repr(e)
    finally:
        r["active_at_end"] = t.is_active()
        t.close()
        r["wire"] = wire
        t0 = r.get("injected_at", 0)
        r["in_after_injection"] = [w["type"] for w in wire if w["dir"] == "in" and w["t"] >= t0]
        r["out_after_injection"] = [w["type"] for w in wire if w["dir"] == "out" and w["t"] >= t0]
    return r


def main():
    out = sys.argv[sys.argv.index("--out") + 1]
    reps = int(sys.argv[sys.argv.index("--reps") + 1])
    res = {"paramiko": paramiko.__version__, "started": datetime.now(timezone.utc).isoformat(), "targets": {}}
    for name, (port, cont) in SUTS.items():
        res["targets"][name] = []
        for mode in ("prerekey_nk_30", "prerekey_nk_nk", "two_channels", "chopen_in_rekey"):
            for _ in range(reps):
                since = datetime.now(timezone.utc).isoformat()
                a = attempt(port, mode)
                time.sleep(0.5)
                a["server_log"] = rp.container_logs(cont, since)
                res["targets"][name].append(a)
                print(f"{name:8} {mode:16} in={a['in_after_injection'][:10]} out={a['out_after_injection'][:8]} "
                      f"rekey={a.get('rekey_completed')} active={a.get('active_after_watch')} auth={a.get('authenticated')} "
                      f"exec={a.get('exec_output', a.get('exec_on_channel2', a.get('exec_error')))!r:.40} "
                      f"ch2={a.get('channel2_opened')} err={a.get('error') or a.get('auth_error')}", flush=True)
    json.dump(res, open(out, "w"), indent=1)


if __name__ == "__main__":
    main()
