"""Differential analysis of learned Mealy machines.

    uv run python -m smlearn.diff results/openssh/model.dot results/dropbear/model.dot

A breadth-first search over the product of two models finds, for every pair of
reachable states, the inputs on which the two implementations answer differently.
Disagreements are grouped by (input, output A, output B) and the shortest witness
of each group is kept, so the report lists distinct behaviours, not every path.
"""

import argparse
import json
from collections import deque
from itertools import combinations
from pathlib import Path

from aalpy.utils import load_automaton_from_file


def load(path):
    return load_automaton_from_file(str(path), "mealy")


def coarse(output: str) -> str:
    """Collapse differences that are about how, not whether, a connection ends."""
    toks = output.split("+")
    if "CLOSED" in toks or "DISCONNECT" in toks:
        return "CLOSED"
    if output == "NO_CONN":
        return "CLOSED"
    return output


def disagreements(m1, m2, alphabet=None, normalize=lambda o: o):
    alphabet = alphabet or sorted(m1.get_input_alphabet())
    start = (m1.initial_state, m2.initial_state)
    seen = {start: ()}
    queue = deque([start])
    groups = {}
    while queue:
        s1, s2 = queue.popleft()
        prefix = seen[(s1, s2)]
        for a in alphabet:
            o1, o2 = s1.output_fun[a], s2.output_fun[a]
            word = prefix + (a,)
            if normalize(o1) != normalize(o2):
                key = (a, normalize(o1), normalize(o2))
                if key not in groups:
                    groups[key] = {"word": list(word), "input": a, "a": o1, "b": o2, "occurrences": 0}
                groups[key]["occurrences"] += 1
                continue
            nxt = (s1.transitions[a], s2.transitions[a])
            if nxt not in seen:
                seen[nxt] = word
                queue.append(nxt)
    return sorted(groups.values(), key=lambda g: (len(g["word"]), g["word"]))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("models", nargs="+", type=Path, help="model.dot files; all pairs are compared")
    p.add_argument("--coarse", action="store_true", help="ignore how a connection is closed")
    p.add_argument("--json", type=Path)
    a = p.parse_args()
    norm = coarse if a.coarse else (lambda o: o)
    report = []
    for p1, p2 in combinations(a.models, 2):
        d = disagreements(load(p1), load(p2), normalize=norm)
        report.append({"a": str(p1), "b": str(p2), "count": len(d), "disagreements": d})
        print(f"\n== {p1.parent.name} vs {p2.parent.name}: {len(d)} distinct disagreements")
        for g in d:
            print(f"  {' '.join(g['word'])}\n      {p1.parent.name}: {g['a']}\n      {p2.parent.name}: {g['b']}")
    if a.json:
        a.json.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
