"""Reviewer probe for D2 (question 1): what exactly does the vendored mapper (with patch P5) put on the wire for
CH_OPEN (and TCP_FORWARD_START), before and after authentication?

Uses the vendored manualparamiko UNCHANGED, driven the same way mapper.py drives it (Dropbear timing profile,
PSM_ALGOS=modern, same env as the psm-mapper-* containers). Instrumentation only:
  - packetizer.send_message is wrapped to record plaintext payload, outgoing sequence number, cipher/MAC state;
  - Transport._send_user_message is wrapped to record that the P5 path ran, the `active` flag and its duration.
Every recorded CHANNEL_OPEN / GLOBAL_REQUEST payload is parsed with STOCK paramiko (independent code).
Run inside a throwaway container of the psm-mapper:pinned image (same Python/paramiko/cryptography as the mappers).

  python3 scratch/review/ch_open_wire.py openssh=2201 dropbear=2202 gossh=2203 --out results/review/ch_open_wire.json
"""
import json
import os
import socket
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VM = os.path.join(ROOT, "vendor", "ssh-fuzzer", "ssh-mapper")
os.environ.update(PSM_ALGOS="modern", PSM_USER="tester", PSM_PASS="correct-horse-battery", PSM_BADPASS="wrong-password")
home = tempfile.mkdtemp(prefix="psm-review-home-")
os.symlink(os.path.join(ROOT, "keys"), os.path.join(home, ".ssh"))
os.environ["HOME"] = home
sys.path[:0] = [VM, os.path.join(VM, "mapper")]

import manualparamiko  # noqa: E402  (vendored, unchanged)
from manualparamiko.transport import Transport as VT  # noqa: E402
from messages import MSG_MAPPING  # noqa: E402
import paramiko  # noqa: E402  (stock, for independent parsing)

SEQS = {
    "pre_nosr_ch_open": ["KEXINIT", "KEX30", "NEWKEYS", "CH_OPEN"],
    "pre_sr_ch_open": ["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "CH_OPEN"],
    "post_auth_ch_open": ["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "UA_PK_OK", "CH_OPEN"],
    "pre_nosr_tcp_forward": ["KEXINIT", "KEX30", "NEWKEYS", "TCP_FORWARD_START"],
}

user_msg_calls = []
_orig_usm = VT._send_user_message


def _usm(self, data):
    t0 = time.time()
    rec = {"active": bool(self.active), "type": data.asbytes()[0]}
    try:
        return _orig_usm(self, data)
    finally:
        rec["seconds"] = round(time.time() - t0, 4)
        user_msg_calls.append(rec)


VT._send_user_message = _usm


def parse(raw):
    t = raw[0]
    m = paramiko.Message(raw[1:])
    if t == 90:
        f = {"kind": m.get_text(), "sender_channel": m.get_int(), "initial_window": m.get_int(),
             "max_packet": m.get_int()}
    elif t == 80:
        f = {"request": m.get_text(), "want_reply": m.get_boolean(), "addr": m.get_text(), "port": m.get_int()}
    else:
        return None
    f["trailing_bytes"] = len(m.get_remainder())
    return f


def run(port, seq):
    del user_msg_calls[:]
    sock = socket.create_connection(("127.0.0.1", port))
    t = manualparamiko.Transport(sock, auth_pw_ok_to=3.0, auth_pw_ok_to_total=3.3, auth_pw_nok_to=0.8,
                                 auth_pw_nok_to_total=1.0, global_to=0.3, global_to_total=0.35,
                                 buffer_after_newkey=False, server=False)
    t.active = True
    banner = t.fuzz_ssh_version()
    sent = []
    pk = t.packetizer
    orig = pk.send_message

    def rec(data):
        raw = data.asbytes()
        sent.append({"type": raw[0], "seq_out": pk._Packetizer__sequence_number_out,
                     "encrypted": pk._Packetizer__block_engine_out is not None,
                     "mac": pk._Packetizer__mac_size_out, "payload_len": len(raw),
                     "payload_hex": raw.hex() if raw[0] in (80, 90) else None, "fields": parse(raw)})
        return orig(data)

    pk.send_message = rec
    outs, step_s = [], []
    for sym in seq:
        t0 = time.time()
        outs.append(getattr(t, MSG_MAPPING[sym])())
        step_s.append(round(time.time() - t0, 3))
        time.sleep(0.25)
    sock.close()
    return {"banner": str(banner), "sequence": seq, "outputs": outs, "step_seconds": step_s, "sent": sent,
            "send_user_message_calls": list(user_msg_calls)}


def main():
    out_path = sys.argv[sys.argv.index("--out") + 1]
    targets = [a for a in sys.argv[1:] if "=" in a]
    res = {"stock_paramiko": paramiko.__version__, "targets": {}}
    for tg in targets:
        name, port = tg.split("=")
        res["targets"][name] = {}
        for mode, seq in SEQS.items():
            r = run(int(port), seq)
            res["targets"][name][mode] = r
            last = r["sent"][-1]
            print(name, mode, r["outputs"], {k: last[k] for k in ("type", "seq_out", "encrypted", "mac", "fields")},
                  r["send_user_message_calls"])
            time.sleep(0.5)
        pre = [s for s in res["targets"][name]["pre_nosr_ch_open"]["sent"] if s["type"] == 90][-1]
        post = [s for s in res["targets"][name]["post_auth_ch_open"]["sent"] if s["type"] == 90][-1]
        res["targets"][name]["ch_open_payload_identical_pre_vs_post"] = pre["payload_hex"] == post["payload_hex"]
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    json.dump(res, open(out_path, "w"), indent=1)


if __name__ == "__main__":
    main()
