"""Reviewer probe for C1-C5: what exactly does the vendored mapper put on the wire, and what comes back, per step?

Uses the vendored manualparamiko UNCHANGED, driven like mapper.py drives it (Dropbear timing profile: 0.3 s per
read, 0.35 s per step; PSM_ALGOS=modern; same env as the psm-mapper-* containers), in a throwaway container of the
psm-mapper:pinned image. Instrumentation only: packetizer.send_message / read_message are wrapped to record, per
abstract step, every packet sent (type, outgoing seq, encrypted?, KEXINIT payload hex) and received (type, UNIMPL's
rejected seq, DISCONNECT text). After the last step one extra 2 s read shows anything that arrives late.

Questions answered:
  C1/P4: is the mapper's pre-auth rekey KEXINIT byte-identical to its post-auth rekey KEXINIT (which OpenSSH accepts)?
  C5:    what does the abstract step "KEX30"/"NEWKEYS" as first input put on the wire (auto-KEXINIT on reading the
         server's KEXINIT)?
  all:   does anything arrive after the 0.35 s window (late DISCONNECT), or is a close hidden behind a message?

  python3 scratch/review/rc_wire.py openssh=2201 dropbear=2202 gossh=2203 --out results/review/rc_wire.json
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
import paramiko  # noqa: E402  (stock, for independent parsing)

PRE = ["KEXINIT", "KEX30", "NEWKEYS"]
SEQS = {
    "c1_pre_nosr": PRE + ["KEXINIT"],
    "c1_pre_sr": PRE + ["SR_AUTH", "KEXINIT"],
    "c1_post": PRE + ["SR_AUTH", "UA_PK_OK", "KEXINIT"],
    "c2_ua_after_success": PRE + ["SR_AUTH", "UA_PK_OK", "UA_PK_OK"],
    "c3_sr_twice": PRE + ["SR_AUTH", "SR_AUTH"],
    "c3_sr_after_auth": PRE + ["SR_AUTH", "UA_PK_OK", "SR_AUTH"],
    "c4_newkeys_first": ["KEXINIT", "NEWKEYS"],
    "c4_dup_kex30": ["KEXINIT", "KEX30", "KEX30"],
    "c4_rekey_newkeys": PRE + ["SR_AUTH", "UA_PK_OK", "KEXINIT", "NEWKEYS", "DEBUG"],
    "c5_kex30_first": ["KEX30"],
    "c5_newkeys_first": ["NEWKEYS"],
}


def run(port, seq):
    sock = socket.create_connection(("127.0.0.1", port))
    t = manualparamiko.Transport(sock, auth_pw_ok_to=3.0, auth_pw_ok_to_total=3.3, auth_pw_nok_to=0.8,
                                 auth_pw_nok_to_total=1.0, global_to=0.3, global_to_total=0.35,
                                 buffer_after_newkey=False, server=False)
    t.active = True
    banner = t.fuzz_ssh_version()
    pk = t.packetizer
    o_send, o_read = pk.send_message, pk.read_message
    steps = []
    cur = {"sent": [], "recv": []}

    def rec_send(data):
        raw = data.asbytes()
        cur["sent"].append({"type": raw[0], "seq_out": pk._Packetizer__sequence_number_out,
                            "encrypted": pk._Packetizer__block_engine_out is not None,
                            "payload_hex": raw.hex() if raw[0] == 20 else None, "payload_len": len(raw)})
        return o_send(data)

    def rec_read():
        ptype, m = o_read()
        e = {"type": ptype, "t": round(time.time() - cur["t0"], 3)}
        try:
            mm = paramiko.Message(m.asbytes())
            if ptype == 3:
                e["unimpl_seq"] = mm.get_int()
            elif ptype == 1:
                e["reason"], e["desc"] = mm.get_int(), mm.get_text()
        except Exception as ex:
            e["decode_error"] = repr(ex)
        cur["recv"].append(e)
        return ptype, m

    pk.send_message, pk.read_message = rec_send, rec_read
    for sym in seq:
        cur = {"sym": sym, "sent": [], "recv": [], "t0": time.time()}
        out = getattr(t, MSG_MAPPING[sym])()
        cur["output"] = out
        cur["seconds"] = round(time.time() - cur["t0"], 3)
        steps.append(cur)
    cur = {"sym": "<late 2s read>", "sent": [], "recv": [], "t0": time.time()}
    try:
        cur["output"] = t.read_multiple_responses(timeout=2.0, total_timeout=2.0)
    except Exception as e:
        cur["output"] = "error " + repr(e)
    steps.append(cur)
    sock.close()
    for s in steps:
        s.pop("t0", None)
    return {"banner": str(banner), "sequence": seq, "outputs": [s["output"] for s in steps], "steps": steps}


def masked(h):
    """KEXINIT payload hex with the 16-byte cookie (bytes 1..16) blanked."""
    return h[:2] + "--" * 16 + h[34:] if h else None


def main():
    out_path = sys.argv[sys.argv.index("--out") + 1]
    res = {"stock_paramiko": paramiko.__version__, "targets": {}}
    for tg in [a for a in sys.argv[1:] if "=" in a]:
        name, port = tg.split("=")
        res["targets"][name] = {}
        for mode, seq in SEQS.items():
            r = run(int(port), seq)
            res["targets"][name][mode] = r
            print(name, mode, r["outputs"])
            for s in r["steps"]:
                print("    ", s["sym"], "sent", [(x["type"], x["seq_out"], x["encrypted"]) for x in s["sent"]],
                      "recv", [(x["type"], x.get("unimpl_seq"), x.get("desc"), x["t"]) for x in s["recv"]])
            time.sleep(0.5)
        # P4 check: KEXINIT payloads per connection
        cmp = {}
        for mode in ("c1_pre_nosr", "c1_pre_sr", "c1_post"):
            k = [x["payload_hex"] for s in res["targets"][name][mode]["steps"] for x in s["sent"] if x["type"] == 20]
            cmp[mode] = {"n_kexinit": len(k), "rekey_identical_to_initial_incl_cookie": len(k) >= 2 and k[0] == k[-1],
                         "rekey_masked": masked(k[-1]) if k else None}
        cmp["pre_vs_post_rekey_identical_except_cookie"] = (
            cmp["c1_pre_nosr"]["rekey_masked"] == cmp["c1_post"]["rekey_masked"] == cmp["c1_pre_sr"]["rekey_masked"])
        for mode in cmp:
            if isinstance(cmp[mode], dict):
                cmp[mode].pop("rekey_masked")
        res["targets"][name]["kexinit_comparison"] = cmp
        print(name, "kexinit_comparison", cmp)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    json.dump(res, open(out_path, "w"), indent=1)


if __name__ == "__main__":
    main()
