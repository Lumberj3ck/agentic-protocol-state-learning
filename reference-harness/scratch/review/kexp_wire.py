"""Mapper wire view for K1-K4, reusing rc_wire.run() (vendored mapper, unchanged, in a throwaway psm-mapper:pinned
container). Per step: packets sent (type, seq, encrypted?, KEXINIT hex) and received (UNIMPL's rejected seq), plus a 2 s
late read. Also checks P4: is the duplicate KEXINIT byte-identical to the first one on the same connection?
  docker run --rm --network host -v $PWD:/w --entrypoint python3 psm-mapper:pinned /w/scratch/review/kexp_wire.py \
      openssh=2201 dropbear=2202 gossh=2203 --out /w/results/review/kexp_wire.json
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rc_wire as rw  # noqa: E402  (sets up the vendored mapper exactly as in the earlier review)

PRE = ["KEXINIT", "KEX30", "NEWKEYS"]
AUTH = PRE + ["SR_AUTH", "UA_PK_OK"]
SEQS = {
    "k1_dup": ["KEXINIT", "KEXINIT"],
    "k1_dup_after30": ["KEXINIT", "KEX30", "KEXINIT"],
    "k2_sr": ["KEXINIT", "SR_AUTH"],
    "k2_sr_after30": ["KEXINIT", "KEX30", "SR_AUTH"],
    "k3_kex30": PRE + ["KEX30"],
    "k3_newkeys": PRE + ["NEWKEYS"],
    "k3_kex30_auth": AUTH + ["KEX30"],
    "k3_newkeys_auth": AUTH + ["NEWKEYS"],
    "k4_dup": AUTH + ["KEXINIT", "KEXINIT"],
    "k4_sr_after30": AUTH + ["KEXINIT", "KEX30", "SR_AUTH"],
    "k4_ua": AUTH + ["KEXINIT", "UA_PK_OK"],
}


def main():
    out_path = sys.argv[sys.argv.index("--out") + 1]
    res = {"targets": {}}
    for tg in [a for a in sys.argv[1:] if "=" in a]:
        name, port = tg.split("=")
        res["targets"][name] = {}
        for mode, seq in SEQS.items():
            r = rw.run(int(port), seq)
            k = [x["payload_hex"] for s in r["steps"] for x in s["sent"] if x["type"] == 20]
            r["kexinit_count"] = len(k)
            r["all_kexinits_identical_incl_cookie"] = len(set(k)) == 1 if k else None
            for s in r["steps"]:
                for x in s["sent"]:
                    x.pop("payload_hex", None)
            res["targets"][name][mode] = r
            print(name, mode, r["outputs"], "kexinits", len(k), "identical", r["all_kexinits_identical_incl_cookie"])
            for s in r["steps"]:
                print("    ", s["sym"], "sent", [(x["type"], x["seq_out"], x["encrypted"]) for x in s["sent"]],
                      "recv", [(x["type"], x.get("unimpl_seq"), x.get("desc"), x["t"]) for x in s["recv"]])
            time.sleep(0.5)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    json.dump(res, open(out_path, "w"), indent=1)


if __name__ == "__main__":
    main()
