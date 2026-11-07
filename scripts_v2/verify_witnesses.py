"""Replay every catalogue witness found on a model of one of OUR servers, with the harness that produced the model
(their verify.py logic, but on our running containers): CONFIRMED if 3 of 3 live runs equal the model's outputs.
  ours:<A|B>_<sut>          -> our mapper (own instance 840x), outputs converted with psm.xharness.ours_output_to_theirs
  theirs-on-our-SUTs:<sut>_<nonstrict|strict|...> -> their mapper with the same strict flag
  .venv-tm/bin/python scripts_v2/verify_witnesses.py results/v2/A/catalogue_results.json --out results/v2/A/catalogue_verified.json"""
import json
import sys

import tm_common as tc

sys.path.insert(0, tc.ROOT)
from psm.mapper_client import MapperClient  # noqa: E402
from psm.xharness import ours_output_to_theirs  # noqa: E402

PORT = {"openssh": 8401, "dropbear": 8402, "gossh": 8403}
NA = {"STRICT-KEX-FIRST-KEXINIT", "STRICT-KEX-NON-KEX-MSG", "STRICT-KEX-REPEATED-MSG"}


def main():
    res = json.load(open(sys.argv[1]))
    out = sys.argv[sys.argv.index("--out") + 1]
    rows = []
    for name, r in res.items():
        kind, _, model = name.partition(":")
        if kind == "theirs-published":
            continue
        sut = model.split("_")[1] if kind == "ours" else model.split("_")[0]
        strict = kind != "ours" and "_strict" in model
        for pid, w in r["hits"].items():
            if not w:
                continue
            word = [s["in"] for s in w]
            expect = [s["out"] for s in w]
            if kind == "ours":
                c = MapperClient("127.0.0.1", PORT[sut])
                ow = ["UA_PK_OK" if x == "UA_PW_OK" else x for x in word]
                live = [[ours_output_to_theirs(o, i == 0) for i, o in enumerate(c.query(ow))] for _ in range(3)]
                c.close()
            else:
                m = tc.tm_mapper(sut, strict)
                live = [tc.tm_query(m, word) for _ in range(3)]
                m.close()
            det = all(x == live[0] for x in live)
            verdict = "CONFIRMED" if det and live[0] == expect else "REFUTED"
            note = "not applicable: our mapper never negotiates strict KEX" if kind == "ours" and pid in NA else ""
            rows.append({"model": name, "pattern": pid, "word": word, "model_out": expect, "live": live,
                         "deterministic": det, "verdict": verdict, "note": note})
            print(f"{name:40} {pid:36} {verdict} {note}", flush=True)
    json.dump(rows, open(out, "w"), indent=1)


if __name__ == "__main__":
    main()
