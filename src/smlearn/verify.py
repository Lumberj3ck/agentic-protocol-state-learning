"""Replay every catalogue witness on the real target: is the violation real, or a model artifact?

    uv run python -m smlearn.verify catalogue/ssh results/runs/<target>-<label>/model.dot ...

A learned model is only a hypothesis: states the equivalence oracle never separated can be merged,
and a catalogue check on the merged model can report behaviour the implementation never shows.
So every witness is run on a fresh container (3 times), and the violation is
CONFIRMED  if the real outputs equal the model's outputs on the witness,
REFUTED    if they differ (the word is then a counterexample for the learner: see --seeds-out).
"""

import argparse
import json
from pathlib import Path

from aalpy.utils import load_automaton_from_file

from smlearn import testbed
from smlearn.catalogue import check, load_catalogue


def target_of(model_path: Path) -> str:
    stats = json.loads((model_path.parent / "learn.json").read_text())
    return stats["target"]


def replay(target_name, words, reps=3, **mapper_kw):
    from smlearn.ssh.mapper import SSHMapper
    target = testbed.load_target(target_name)
    testbed.build(target)
    inst = testbed.start(target)
    try:
        m = SSHMapper(inst.host, inst.port, user=target.user, password=target.password, **mapper_kw)
        out = []
        for w in words:
            runs = []
            for _ in range(reps):
                m.reset()
                runs.append([m.step(i) for i in w])
            out.append(runs)
        m.close()
        return out
    finally:
        inst.stop()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("catalogue", type=Path)
    p.add_argument("models", nargs="+", type=Path)
    p.add_argument("--json", type=Path, help="write per-model verdicts here")
    p.add_argument("--seeds-out", type=Path, help="write refuted witnesses (JSON list of words) here")
    a = p.parse_args()
    patterns = load_catalogue(a.catalogue)
    report, refuted_words = {}, []
    for mp in a.models:
        model = load_automaton_from_file(str(mp), "mealy")
        name = target_of(mp)
        hits = [(pat, check(model, pat)) for pat in patterns]
        hits = [(pat, w) for pat, w in hits if w]
        words = [[s["in"] for s in w] for _, w in hits]
        runs = replay(name, words, timeout=0.4, quiet=0.1) if words else []
        report[str(mp)] = []
        for (pat, w), word, r in zip(hits, words, runs):
            expected = [s["out"] for s in w]
            deterministic = all(x == r[0] for x in r)
            verdict = "CONFIRMED" if deterministic and r[0] == expected else "REFUTED"
            if verdict == "REFUTED":
                refuted_words.append(word)
            report[str(mp)].append({"pattern": pat["id"], "level": pat["level"], "word": word,
                                    "model": expected, "real": r[0], "deterministic": deterministic,
                                    "verdict": verdict})
            print(f"{name:20} {pat['id']:26} {verdict}")
            if verdict == "REFUTED":
                diff = next(k for k, (x, y) in enumerate(zip(expected, r[0])) if x != y)
                print(f"    at step {diff + 1} ({word[diff]}): model {expected[diff]}, real {r[0][diff]}")
    if a.json:
        a.json.write_text(json.dumps(report, indent=2) + "\n")
    if a.seeds_out:
        a.seeds_out.write_text(json.dumps(refuted_words, indent=2) + "\n")


if __name__ == "__main__":
    main()
