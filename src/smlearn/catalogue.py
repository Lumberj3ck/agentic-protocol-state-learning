"""Check learned models against a catalogue of state machine bug patterns.

    uv run python -m smlearn.catalogue catalogue/ssh results/*/model.dot

Following the automata-based approach (bug patterns as finite automata over
input/output pairs), each catalogue entry is a JSON file describing a small,
possibly nondeterministic automaton. A model violates the entry if some input
word drives the product of model and pattern into an accepting pattern state.
The shortest such word is reported as a witness, to be replayed on the real target.

Pattern transition fields (all optional; a missing field matches anything):
  "in":        input symbol or list of symbols
  "in_not":    list of input symbols that must not match
  "out_has":   list of output tokens; matches if any is present
  "out_lacks": list of output tokens; matches if none is present
Output tokens are the parts of an output split on "+".
"""

import argparse
import json
from collections import deque
from pathlib import Path

from aalpy.utils import load_automaton_from_file


def matches(t, inp, out):
    toks = set(out.split("+"))
    if "in" in t:
        allowed = t["in"] if isinstance(t["in"], list) else [t["in"]]
        if inp not in allowed:
            return False
    if inp in t.get("in_not", []):
        return False
    if "out_has" in t and not toks & set(t["out_has"]):
        return False
    if toks & set(t.get("out_lacks", [])):
        return False
    return True


def check(model, pattern, alphabet=None):
    """Return the shortest witness word violating `pattern`, or None."""
    auto = pattern["automaton"]
    alphabet = alphabet or sorted(model.get_input_alphabet())
    accept = set(auto["accept"])
    start = (model.initial_state, auto["initial"])
    seen = {start: ()}
    queue = deque([start])
    while queue:
        ms, ps = queue.popleft()
        word = seen[(ms, ps)]
        for a in alphabet:
            out = ms.output_fun[a]
            for t in auto["transitions"]:
                if t["from"] == ps and matches(t, a, out):
                    nxt = (ms.transitions[a], t["to"])
                    if nxt in seen:
                        continue
                    seen[nxt] = word + ((a, out),)
                    if t["to"] in accept:
                        return [{"in": i, "out": o} for i, o in seen[nxt]]
                    queue.append(nxt)
    return None


def load_catalogue(path: Path):
    return [json.loads(f.read_text()) | {"file": f.name} for f in sorted(path.glob("*.json"))]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("catalogue", type=Path)
    p.add_argument("models", nargs="+", type=Path)
    p.add_argument("--json", type=Path)
    a = p.parse_args()
    patterns = load_catalogue(a.catalogue)
    report = {}
    for mp in a.models:
        model = load_automaton_from_file(str(mp), "mealy")
        name = mp.parent.name
        report[name] = {}
        for pat in patterns:
            w = check(model, pat)
            report[name][pat["id"]] = w
            status = "VIOLATED" if w else "ok"
            print(f"{name:12} {pat['id']:24} {status}")
            if w:
                print("    " + "  ".join(f"{s['in']}/{s['out']}" for s in w))
    if a.json:
        a.json.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
