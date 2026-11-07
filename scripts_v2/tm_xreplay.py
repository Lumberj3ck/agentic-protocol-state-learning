"""Fast harness differential: replay our v1 sequences through THE TEAMMATE'S mapper on our live SUTs and compare
step by step with our recorded mapper outputs (results/final/verified_all.json, results/final/final_check_replay.json),
after the vocabulary map in results/v2/A/alphabet_map.json.
  .venv-tm/bin/python scripts_v2/tm_xreplay.py --strict 0 --reps 3 --out results/v2/A/xreplay_nonstrict.json"""
import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import tm_common as tc

sys.path.insert(0, tc.ROOT)
from psm.taint import first_tainted_index  # noqa: E402

IN_MAP = {"UA_PK_OK": "UA_PW_OK"}
TOK = {"UNIMPLEMENTED": "UNIMPL", "SERVICE_ACCEPT": "SR_ACCEPT"}
DROP = {"IGNORE", "DEBUG", "EXT_INFO"}  # EXT_INFO: only ours advertises ext-info-c (RFC 8308)


def map_theirs(o):
    toks = [TOK.get(t, t) for t in o.split("+") if t not in DROP]
    if toks == ["CLOSED"]:
        return "NO_CONN"
    toks = [t for t in toks if t != "CLOSED"]
    s = "+".join(toks) if toks else "NO_RESP"
    return "UA_SUCCESS" if s == "UA_SUCCESS+GLOBAL_REQUEST" else s


def map_ours(o, step):
    toks = [t for t in o.split("+") if t != "EXT_INFO"]
    if step == 0 and toks and toks[0] == "KEXINIT":
        toks = toks[1:]
    s = "+".join(toks) if toks else "NO_RESP"
    return "UA_SUCCESS" if s == "UA_SUCCESS+GLOBAL_REQUEST" else s


def load_ours():
    rows = json.load(open(os.path.join(tc.ROOT, "results/final/verified_all.json")))["rows"]
    seqs = {}
    for r in rows:
        seqs.setdefault(tuple(r["sequence"]), {"outputs": r["outputs"], "src": r["replay_file"]})
    fc = json.load(open(os.path.join(tc.ROOT, "results/final/final_check_replay.json")))
    for e in fc["sequences"]:
        k = tuple(e["sequence"])
        if k not in seqs:
            seqs[k] = {"outputs": {n: r["distinct"][0]["outputs"] for n, r in e["results"].items()},
                       "src": "results/final/final_check_replay.json"}
    return seqs


def classify(seq, ours_raw, i):
    if seq[0] != "KEXINIT":
        return "setup: auto-KEXINIT (first input not KEXINIT)"
    t = first_tainted_index(seq, ours_raw)
    if t is not None and i >= t:
        return "ours wrong (known): NEWKEYS without completed KEX corrupts our stream"
    if "CH_MAX" in ours_raw[i]:
        return "not comparable: CH_MAX"
    return "UNCLASSIFIED"


def run(sut, strict, seq, reps):
    m = tc.tm_mapper(sut, strict)
    word = [IN_MAP.get(x, x) for x in seq]
    runs = []
    for _ in range(reps):
        for k in range(4):
            try:
                runs.append(tc.tm_query(m, word))
                break
            except (EOFError, OSError):
                time.sleep(0.3 * 2 ** k)
    trace = [(d, n) for d, n, _ in m.trace]
    active = m.strict_kex_active
    m.close()
    return {"runs": runs, "trace_last": trace, "strict_kex_active": active}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", type=int, default=0)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    ours = load_ours()
    jobs = [(sut, seq) for seq in ours for sut in ("openssh", "dropbear", "gossh")]
    with ThreadPoolExecutor(a.workers * 3) as ex:
        res = list(ex.map(lambda j: run(j[0], bool(a.strict), list(j[1]), a.reps), jobs))
    rows = []
    for (sut, seq), r in zip(jobs, res):
        o_raw = ours[seq]["outputs"][sut]
        det = len({tuple(x) for x in r["runs"]}) == 1 and len(r["runs"]) == a.reps
        t_raw = r["runs"][0] if r["runs"] else []
        o_m = [map_ours(o, i) for i, o in enumerate(o_raw)]
        t_m = [map_theirs(o) for o in t_raw]
        first = next((i for i, (x, y) in enumerate(zip(o_m, t_m)) if x != y), None)
        rows.append({"sut": sut, "sequence": list(seq), "ours_raw": o_raw, "ours_src": ours[seq]["src"],
                     "theirs_raw_runs": r["runs"], "theirs_deterministic": det, "ours_mapped": o_m, "theirs_mapped": t_m,
                     "first_mismatch": first, "strict_kex_active": r["strict_kex_active"],
                     "class": None if first is None else classify(list(seq), o_raw, first),
                     "theirs_trace_last_run": r["trace_last"]})
    json.dump({"strict_kex": bool(a.strict), "reps": a.reps, "timing": tc.TM_TIMING, "rows": rows}, open(a.out, "w"), indent=1)
    n = len(rows)
    mm = [r for r in rows if r["first_mismatch"] is not None]
    print(f"{n} (sut,sequence) pairs, {len(mm)} mismatches, nondet {sum(not r['theirs_deterministic'] for r in rows)}")
    for r in mm:
        i = r["first_mismatch"]
        print(f"{r['sut']:8} {' '.join(r['sequence'][:i])} **{r['sequence'][i]}** ours={r['ours_mapped'][i]} theirs={r['theirs_mapped'][i]} [{r['class']}]")


if __name__ == "__main__":
    main()
