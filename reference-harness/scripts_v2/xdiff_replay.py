"""For every cross-harness model disagreement class (psm.xharness diff JSON), replay the representative sequence
with OUR mapper (own instance, psm.mapper_client) and THEIR mapper on the live server, 3 reps each, and record whether
each live trace matches its own model and whether the two live traces agree after the vocabulary map.
  .venv-tm/bin/python scripts_v2/xdiff_replay.py --pair openssh=results/v2/A/xdiff_openssh.json:8401 ... --strict 0 --out ..."""
import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor

import tm_common as tc

sys.path.insert(0, tc.ROOT)
from psm.mapper_client import MapperClient  # noqa: E402
from psm.taint import first_tainted_index  # noqa: E402
from psm.xharness import map_ours_output, map_theirs_output  # noqa: E402


def ours_runs(port, seq, reps):
    c = MapperClient("127.0.0.1", port)
    r = [c.query(seq) for _ in range(reps)]
    c.close()
    return r


def theirs_runs(sut, strict, seq, reps):
    m = tc.tm_mapper(sut, strict)
    w = ["UA_PW_OK" if x == "UA_PK_OK" else x for x in seq]
    r = [tc.tm_query(m, w) for _ in range(reps)]
    m.close()
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pair", action="append", required=True, help="sut=xdiff.json:our_mapper_port")
    ap.add_argument("--strict", type=int, default=0)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    rows = []
    for p in a.pair:
        sut, rest = p.split("=")
        path, port = rest.rsplit(":", 1)
        d = json.load(open(path))
        for c in d["classes"]:
            seq = c["sequence"]
            with ThreadPoolExecutor(2) as ex:
                fo = ex.submit(ours_runs, int(port), seq, a.reps)
                ft = ex.submit(theirs_runs, sut, bool(a.strict), seq, a.reps)
                o, t = fo.result(), ft.result()
            om = [map_ours_output(x, i == 0) for i, x in enumerate(o[0])]
            tm = [map_theirs_output(x) for x in t[0]]
            first = next((i for i, (x, y) in enumerate(zip(om, tm)) if x != y), None)
            row = {"sut": sut, "sequence": seq, "model_ours": c["trace1"], "model_theirs": c["trace2"],
                   "live_ours_raw": o, "live_theirs_raw": t,
                   "ours_det": all(x == o[0] for x in o), "theirs_det": all(x == t[0] for x in t),
                   "live_ours": om, "live_theirs": tm,
                   "ours_live_matches_model": om == c["trace1"], "theirs_live_matches_model": tm == c["trace2"],
                   "live_first_mismatch": first, "ours_taint_index": first_tainted_index(seq, o[0]),
                   "auto_kexinit": seq[0] != "KEXINIT", "comparable": c["comparable"]}
            rows.append(row)
            print(f"{sut:8} {' '.join(seq)}\n   model ours={c['trace1'][-1]} theirs={c['trace2'][-1]} | live ours={om[-1]} theirs={tm[-1]}"
                  f" | live-agree={first is None} ours-model-ok={row['ours_live_matches_model']} theirs-model-ok={row['theirs_live_matches_model']}"
                  f" taint={row['ours_taint_index']} det={row['ours_det']}/{row['theirs_det']}", flush=True)
    json.dump({"strict_kex": bool(a.strict), "reps": a.reps, "rows": rows}, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
