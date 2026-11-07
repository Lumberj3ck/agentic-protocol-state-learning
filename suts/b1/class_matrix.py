"""Build results/v2/B1/class_matrix.md: rows = implementations, columns = D1..D9 (+control), cell = abstract output at the
divergence point (last output of the representative sequence, majority over reps; '*' = not deterministic across reps).
Inputs: results/final/final_check_replay.json (openssh/dropbear/gossh) and results/v2/B1/<impl>_final_seqs.json."""
import glob, json, os
REP = {"ctrl": "KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK CH_OPEN", "D1": "KEXINIT KEX30 NEWKEYS UA_PK_OK",
       "D2": "KEXINIT KEX30 NEWKEYS SR_AUTH CH_OPEN", "D3": "KEXINIT KEX30 NEWKEYS SR_AUTH KEXINIT",
       "D4": "KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK UA_PK_OK", "D5": "KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK SR_AUTH",
       "D6": "KEXINIT KEX30 NEWKEYS SR_AUTH SR_CONN", "D7": "KEXINIT KEX30 KEX30", "D8": "KEX30", "D9": "KEXINIT KEXINIT"}
rows = {}; full = {}
def load(path):
    d = json.load(open(path))
    for e in d["sequences"]:
        for t, r in e["results"].items():
            top = r["distinct"][0]
            rows.setdefault(t, {})[" ".join(e["sequence"])] = (top["outputs"][-1] + ("" if r["deterministic"] else "*"), top["outputs"])
load("results/final/final_check_replay.json")
for p in sorted(glob.glob("results/v2/B1/*_final_seqs.json")):
    load(p)
order = ["openssh", "dropbear", "gossh"] + sorted(t for t in rows if t not in ("openssh", "dropbear", "gossh"))
out = ["# Class matrix: output at the divergence point (last abstract output of the D1-D9 representative sequence)", "",
       "Source: `results/final/final_check_replay.json` (5 reps) and `results/v2/B1/<impl>_final_seqs.json` (3 reps); `*` = not deterministic over reps.",
       "Representatives: " + "; ".join(f"{k} = `{v}`" for k, v in REP.items()), "",
       "| impl | " + " | ".join(REP) + " |", "|---|" + "---|" * len(REP)]
for t in order:
    out.append(f"| {t} | " + " | ".join(rows[t].get(s, ("-", 0))[0] for s in REP.values()) + " |")
out += ["", "## Full output traces", ""]
for t in order:
    out.append(f"### {t}")
    for k, s in REP.items():
        if s in rows[t]: out.append(f"- {k}: `{' '.join(rows[t][s][1])}`")
open("results/v2/B1/class_matrix.md", "w").write("\n".join(out) + "\n")
print("\n".join(out[:12 + len(order)]))
