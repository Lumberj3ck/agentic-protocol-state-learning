"""Run the teammate's catalogue (vendor/.../catalogue/ssh) and our D1-D9 candidate patterns (catalogue-v2/) on:
our v1 models (converted to their vocabulary by psm.xharness.ours_to_theirs), their published models
(vendor/.../results/runs/*/model.dot) and the models their learner produced on our SUTs (results/v2/A/tm_models/*).
Uses their checker (smlearn.catalogue.check) unchanged.
  .venv-tm/bin/python scripts_v2/run_catalogues.py --out results/v2/A/catalogue_results.json"""
import glob
import json
import os
import sys

import tm_common as tc

sys.path.insert(0, tc.ROOT)
from aalpy.utils import load_automaton_from_file  # noqa: E402
from smlearn.catalogue import check, load_catalogue  # noqa: E402
from pathlib import Path  # noqa: E402
from psm.xharness import ours_to_theirs  # noqa: E402

TM = os.path.join(tc.ROOT, "vendor", "agentic-protocol-state-learning")


def models():
    for p in sorted(glob.glob(os.path.join(tc.ROOT, "results/models/[AB]_*.dot"))):
        if "stateprefix" in p:
            continue
        yield "ours:" + os.path.basename(p)[:-4], p, True
    for p in sorted(glob.glob(os.path.join(TM, "results/runs/*/model.dot"))):
        yield "theirs-published:" + p.split("/")[-2], p, False
    for p in sorted(glob.glob(os.path.join(tc.ROOT, "results/v2/A/tm_models/*/model.dot"))):
        yield "theirs-on-our-SUTs:" + p.split("/")[-2], p, False


def main():
    out = sys.argv[sys.argv.index("--out") + 1]
    cats = {"teammate": load_catalogue(Path(TM) / "catalogue/ssh"), "D1-D9": load_catalogue(Path(tc.ROOT) / "catalogue-v2")}
    res = {}
    for name, path, convert in models():
        m = load_automaton_from_file(path, "mealy")
        if convert:
            m = ours_to_theirs(m)
        res[name] = {"path": os.path.relpath(path, tc.ROOT), "converted": convert, "states": len(m.states),
                     "alphabet": sorted(m.get_input_alphabet()), "hits": {}}
        for cname, pats in cats.items():
            for pat in pats:
                w = check(m, pat)
                res[name]["hits"][pat["id"]] = w
        hits = [k for k, v in res[name]["hits"].items() if v]
        print(f"{name:45} {len(m.states):3}  {', '.join(hits)}")
    json.dump(res, open(out, "w"), indent=1)


if __name__ == "__main__":
    main()
