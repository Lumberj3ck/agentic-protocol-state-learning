"""Reviewer probe (hypothesis 1): what exactly does the vendored mapper put on the wire for UA_PK_OK,
with and without a preceding SR_AUTH?

Uses the vendored manualparamiko UNCHANGED, driven the same way mapper.py drives it (Dropbear timing profile,
PSM_ALGOS=modern, same env as the psm-mapper-* containers). Only instrumentation: the packetizer's send_message
is wrapped to record the plaintext payload, the outgoing sequence number and whether an outbound cipher is active.
The recorded USERAUTH_REQUEST is parsed and its signature is checked with STOCK paramiko (independent code).

  .venv/bin/python scratch/review/mapper_wire.py openssh=2201 dropbear=2202 gossh=2203 --out results/review/mapper_wire.json
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
from messages import MSG_MAPPING  # noqa: E402
import paramiko  # noqa: E402  (stock, for independent signature verification)

SEQS = {
    "no_sr": ["KEXINIT", "KEX30", "NEWKEYS", "UA_PK_OK"],
    "with_sr": ["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "UA_PK_OK"],
}


def run(port, seq):
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
                     "mac": pk._Packetizer__mac_size_out, "payload_hex": raw.hex()})
        return orig(data)

    pk.send_message = rec
    outs = []
    for sym in seq:
        outs.append(getattr(t, MSG_MAPPING[sym])())
        time.sleep(0.25)
    sid = t.session_id
    sock.close()
    ua = [s for s in sent if s["type"] == 50][-1]
    m = paramiko.Message(bytes.fromhex(ua["payload_hex"])[1:])
    f = {"user": m.get_text(), "service": m.get_text(), "method": m.get_text(), "has_sig": m.get_boolean(),
         "alg": m.get_text()}
    keyblob = m.get_binary()
    sig = m.get_binary()
    trailing = m.get_remainder()
    blob = paramiko.Message()
    blob.add_string(sid)
    blob.add_byte(bytes([50]))
    blob.add_string(f["user"])
    blob.add_string(f["service"])
    blob.add_string("publickey")
    blob.add_boolean(True)
    blob.add_string(f["alg"])
    blob.add_string(keyblob)
    key = paramiko.RSAKey(data=keyblob)
    authorized = open(os.path.join(ROOT, "keys", "id_rsa.pub")).read().split()[1]
    import base64
    f.update(
        keyblob_is_authorized_key=keyblob == base64.b64decode(authorized),
        sig_valid_over_real_session_id=key.verify_ssh_sig(blob.asbytes(), paramiko.Message(sig)),
        session_id_is_placeholder=(sid is None or sid == "SESID"),
        session_id_prefix=sid.hex()[:16] if isinstance(sid, bytes) else repr(sid),
        trailing_bytes=len(trailing),
        payload_len=len(bytes.fromhex(ua["payload_hex"])),
        seq_out=ua["seq_out"], encrypted=ua["encrypted"], mac_size=ua["mac"],
    )
    return {"banner": str(banner), "outputs": outs, "sent": [{k: v for k, v in s.items() if k != "payload_hex"}
                                                             for s in sent], "ua_request": f}


def main():
    out_path = sys.argv[sys.argv.index("--out") + 1]
    targets = [a for a in sys.argv[1:] if "=" in a]
    res = {}
    for t in targets:
        name, port = t.split("=")
        res[name] = {}
        for mode, seq in SEQS.items():
            res[name][mode] = run(int(port), seq)
            time.sleep(0.5)
        a, b = res[name]["no_sr"]["ua_request"], res[name]["with_sr"]["ua_request"]
        res[name]["fields_identical_except_seq"] = {k: a[k] == b[k] for k in a if k not in ("seq_out", "session_id_prefix")}
        print(name, json.dumps(res[name]["fields_identical_except_seq"]))
        for mode in SEQS:
            r = res[name][mode]
            print("  ", mode, r["outputs"], {k: r["ua_request"][k] for k in ("seq_out", "encrypted", "sig_valid_over_real_session_id", "service", "user", "alg")})
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    json.dump(res, open(out_path, "w"), indent=1)


if __name__ == "__main__":
    main()
