"""Turn a multi-server replay into the list of REPORTABLE disagreements.

A replayed sequence is reportable only if (1) every server answered it identically in every repetition,
(2) the servers' outputs differ, and (3) no server's trace is harness-tainted (psm.taint) at or before the first
divergence. Everything else is listed with the reason it was discarded.

  python -m psm.verify results/replay/final.json --out results/final/verified
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from psm.taint import first_tainted_index


def classify(entry: dict, norm: dict | None = None) -> dict:
    norm = norm or {}
    res = entry["results"]
    seq = entry["sequence"]
    names = list(res)
    row = {"sequence": seq, "outputs": {}, "status": None, "reason": None, "divergence_index": None,
           "groups": None}
    if not all(r["deterministic"] for r in res.values()):
        row["status"], row["reason"] = "discarded", "nondeterministic on " + ",".join(n for n in names if not res[n]["deterministic"])
        row["outputs"] = {n: [" ".join(d["outputs"]) + f" (x{d['count']})" for d in res[n]["distinct"]] for n in names}
        return row
    raw = {n: res[n]["distinct"][0]["outputs"] for n in names}
    outs = {n: [norm.get(o, o) for o in raw[n]] for n in names}
    row["outputs"] = outs
    if any(raw[n] != outs[n] for n in names):
        row["raw_outputs"] = raw
    div = next((i for i in range(len(seq)) if len({tuple(outs[n][:i + 1]) for n in names}) > 1), None)
    if div is None:
        row["status"], row["reason"] = "agree", "all servers identical"
        return row
    row["divergence_index"] = div
    taints = {n: first_tainted_index(seq, outs[n]) for n in names}
    bad = [n for n, t in taints.items() if t is not None and t <= div]
    if bad:
        row["status"], row["reason"] = "discarded", f"harness-tainted before divergence on {','.join(bad)} (NEWKEYS without completed KEX)"
        return row
    groups = {}
    for n in names:
        groups.setdefault(outs[n][div], []).append(n)
    row["groups"] = groups
    row["status"] = "reportable"
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("replays", nargs="+")
    ap.add_argument("--out", required=True, help="output prefix (writes .json and .md)")
    ap.add_argument("--normalize", help="JSON map output-symbol -> replacement (documented extension messages)")
    a = ap.parse_args()
    norm = json.loads(Path(a.normalize).read_text()) if a.normalize else {}
    rows, seen = [], set()
    for p in a.replays:
        for e in json.loads(Path(p).read_text())["sequences"]:
            if tuple(e["sequence"]) in seen:
                continue
            seen.add(tuple(e["sequence"]))
            r = classify(e, norm)
            r["replay_file"] = p
            rows.append(r)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out + ".json").write_text(json.dumps({"normalize": norm, "rows": rows}, indent=1))
    md = [f"Normalization applied before comparing: {json.dumps(norm)} (raw outputs kept in the .json)", "",
          "| # | status | sequence (divergence at the marked input) | outputs at divergence | reason | evidence |",
          "|---|---|---|---|---|---|"]
    for i, r in enumerate(rows, 1):
        seq = list(r["sequence"])
        if r["divergence_index"] is not None:
            seq[r["divergence_index"]] = f"**{seq[r['divergence_index']]}**"
        at = "; ".join(f"{k}: {', '.join(v)}" for k, v in (r["groups"] or {}).items())
        md.append(f"| {i} | {r['status']} | {' '.join(seq)} | {at} | {r['reason'] or ''} | `{r['replay_file']}` |")
    Path(a.out + ".md").write_text("\n".join(md) + "\n")
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print(counts)


if __name__ == "__main__":
    main()
