"""Check a learned model against replayed traces: does the model predict every observed output?

  python -m psm.check_traces results/models/x.dot results/replay/a.json[:target] ... --out results/checks/x.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from psm.diff import load_mealy


def predict(model, seq):
    model.reset_to_initial()
    out = []
    for x in seq:
        if x not in model.get_input_alphabet():
            return None
        out.append(model.step(x))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("model")
    ap.add_argument("replays", nargs="+", help="replay json, optionally :target to pick one target")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    m = load_mealy(a.model)
    rows = []
    for spec in a.replays:
        path, _, target = spec.partition(":")
        data = json.loads(Path(path).read_text())
        for e in data["sequences"]:
            for name, r in e["results"].items():
                if target and name != target:
                    continue
                for d in r["distinct"]:
                    p = predict(m, e["sequence"])
                    rows.append({"replay": path, "target": name, "sequence": e["sequence"], "observed": d["outputs"],
                                 "predicted": p, "match": p == d["outputs"] if p is not None else None})
    res = {"model": a.model, "checked": len(rows), "mismatches": [r for r in rows if r["match"] is False],
           "skipped_alphabet": sum(r["match"] is None for r in rows), "rows": rows}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=1))
    print(f"{a.model}: {len(rows)} traces, {len(res['mismatches'])} mismatches, {res['skipped_alphabet']} outside alphabet")
    for r in res["mismatches"]:
        print("  MISMATCH", " ".join(r["sequence"]), "\n    observed ", " ".join(r["observed"]), "\n    predicted", " ".join(r["predicted"]))


if __name__ == "__main__":
    main()
