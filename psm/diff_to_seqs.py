"""Extract every distinguishing sequence (representatives of all fine classes, plus their examples) from a
psm.diff JSON (pairwise or n-way) into a replay sequence file, de-duplicated and sorted by length.

  python -m psm.diff_to_seqs results/diff/A_all.json --out results/diff/A_all_seqs.json
"""
import argparse
import json
from pathlib import Path


def sequences(diff: dict) -> list[list[str]]:
    pairs = diff["pairs"].values() if "pairs" in diff else [diff]
    seen = set()
    for p in pairs:
        for c in p.get("classes", []):
            for s in [c["sequence"]] + [e if isinstance(e, list) else e.get("sequence") for e in c.get("examples", [])]:
                if s:
                    seen.add(tuple(s))
    return [list(s) for s in sorted(seen, key=lambda s: (len(s), s))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("diff")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    seqs = sequences(json.loads(Path(a.diff).read_text()))
    Path(a.out).write_text(json.dumps(seqs))
    print(f"{len(seqs)} sequences -> {a.out}")


if __name__ == "__main__":
    main()
