"""v2: version x class matrix. For each class representative (reference/final_check_seqs.json, classified in
results/final/final_check_verified.json), the output each server gives at the v1 divergence index, after the
documented normalisation. Change points between consecutive versions of one implementation are marked.

  python -m psm.class_matrix --reference results/final/final_check_verified.json results/v2/B2/*.json \
      --order openssh-7.5_p1 ... --out results/v2/B2/class_matrix
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

CLASS_OF = {  # representative sequence -> class id (report.md v1 table)
    "KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK CH_OPEN": "control",
    "KEXINIT KEX30 NEWKEYS UA_PK_OK": "D1",
    "KEXINIT KEX30 NEWKEYS SR_AUTH CH_OPEN": "D2",
    "KEXINIT KEX30 NEWKEYS SR_AUTH KEXINIT": "D3",
    "KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK UA_PK_OK": "D4",
    "KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK SR_AUTH": "D5",
    "KEXINIT KEX30 NEWKEYS SR_AUTH SR_CONN": "D6",
    "KEXINIT KEX30 KEX30": "D7",
    "KEX30": "D8",
    "KEXINIT KEXINIT": "D9",
    "KEXINIT KEX30 NEWKEYS SR_AUTH UA_PK_OK KEXINIT SR_AUTH": "D9b",
}


def cells(replay: dict, div: dict, norm: dict) -> dict:
    """{target: {class: cell}}; cell = output at divergence index, or full trace for the control."""
    out = {}
    for e in replay["sequences"]:
        key = " ".join(e["sequence"])
        cls = CLASS_OF.get(key)
        if cls is None:
            continue
        for name, r in e["results"].items():
            if not r["deterministic"]:
                cell = "NONDET " + " / ".join(" ".join(d["outputs"]) for d in r["distinct"])
            else:
                outs = [norm.get(o, o) for o in r["distinct"][0]["outputs"]]
                i = div.get(key)
                cell = " ".join(outs) if (cls == "control" or i is None) else outs[i]
                # was the prefix before the divergence the normal one? if not, say so
                if cls != "control" and i is not None and outs[:i] != div["_prefix"][key]:
                    cell += " (prefix differs: " + " ".join(outs[:i]) + ")"
            out.setdefault(name, {})[cls] = cell
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reference", required=True, help="final_check_verified.json (gives divergence indices)")
    ap.add_argument("replays", nargs="+")
    ap.add_argument("--normalize", default="reference/normalize.json")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    norm = json.loads(Path(a.normalize).read_text())
    ref = json.loads(Path(a.reference).read_text())
    div, prefix = {}, {}
    for r in ref["rows"]:
        k = " ".join(r["sequence"])
        div[k] = r["divergence_index"]
        any_out = next(iter(r["outputs"].values()))
        prefix[k] = any_out[:r["divergence_index"]] if r["divergence_index"] is not None else None
    div["_prefix"] = prefix
    table = {}
    for p in a.replays:
        try:
            table.update(cells(json.loads(Path(p).read_text()), div, norm))
        except Exception as e:  # a failed target is reported, not fatal
            table[Path(p).stem] = {"control": f"unreadable: {e}"}
    classes = list(dict.fromkeys(CLASS_OF.values()))
    Path(a.out + ".json").write_text(json.dumps(table, indent=1))
    md = ["| server | " + " | ".join(classes) + " |", "|" + "---|" * (len(classes) + 1)]
    prev_impl, prev = None, None
    for name in table:
        impl = name.split("-")[0]
        row = []
        for c in classes:
            v = table[name].get(c, "")
            changed = impl == prev_impl and prev is not None and prev.get(c) != v and c != "control"
            row.append(("**" + v + "** (changed)") if changed else v)
        md.append(f"| {name} | " + " | ".join(row) + " |")
        prev_impl, prev = impl, table[name]
    Path(a.out + ".md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
