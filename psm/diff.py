"""Diff two (or more) learned Mealy machines via BFS over their product automaton.

CLI:
    python -m psm.diff A.dot B.dot --out results/diff/A__vs__B.json [--names a b] [--normalize map.json]
    python -m psm.diff A.dot B.dot C.dot --out results/diff/all.json [--names a b c]   # n-way
"""
import argparse
import itertools
import json
import os
import sys
from collections import deque

UNDEF = "<undefined>"


def load_mealy(path):
    from aalpy.utils import load_automaton_from_file
    return load_automaton_from_file(str(path), automaton_type="mealy")


def _alphabet(m):
    ins = set()
    for s in m.states:
        ins.update(s.transitions.keys())
    return sorted(ins)


def alphabet_report(m1, m2):
    a1, a2 = _alphabet(m1), _alphabet(m2)
    return {"alphabet1": a1, "alphabet2": a2,
            "common": sorted(set(a1) & set(a2)),
            "only_in_1": sorted(set(a1) - set(a2)),
            "only_in_2": sorted(set(a2) - set(a1)),
            "identical": a1 == a2}


def _out(s, i):
    return s.output_fun.get(i, UNDEF)


def _next(s, i):
    return s.transitions.get(i)


def run_trace(m, seq):
    """Output trace of machine m along input sequence seq."""
    s, tr = m.initial_state, []
    for i in seq:
        tr.append(_out(s, i))
        s = _next(s, i)
        if s is None:
            break
    return tr


def distinguishing_sequences(m1, m2, inputs=None):
    """All first-divergence points of the product automaton, in BFS (shortest-first) order.

    Each record: access (shortest input prefix), input, out1, out2, trace1/trace2 (outputs along
    access+[input]), state1/state2 (source state ids).  Successors of differing transitions are not
    expanded; agreeing transitions are.
    """
    if inputs is None:
        inputs = alphabet_report(m1, m2)["common"]
    inputs = sorted(inputs)
    start = (m1.initial_state, m2.initial_state)
    seen = {(id(start[0]), id(start[1]))}
    q = deque([(start[0], start[1], (), (), ())])
    found = []
    while q:
        s1, s2, acc, t1, t2 = q.popleft()
        for i in inputs:
            o1, o2 = _out(s1, i), _out(s2, i)
            if o1 != o2:
                found.append({"access": list(acc), "input": i, "out1": o1, "out2": o2,
                              "trace1": list(t1) + [o1], "trace2": list(t2) + [o2],
                              "state1": str(s1.state_id), "state2": str(s2.state_id)})
                continue
            n1, n2 = _next(s1, i), _next(s2, i)
            if n1 is None or n2 is None:
                continue
            k = (id(n1), id(n2))
            if k not in seen:
                seen.add(k)
                q.append((n1, n2, acc + (i,), t1 + (o1,), t2 + (o2,)))
    return found


def are_equivalent(m1, m2, inputs=None):
    if inputs is None and not alphabet_report(m1, m2)["identical"]:
        return False
    return not distinguishing_sequences(m1, m2, inputs)


def _seq(d):
    return d["access"] + [d["input"]]


def group_disagreements(ds, coarse=False, n_examples=3):
    """Group disagreements into classes.

    Fine key: (input, out1, out2, state1, state2); coarse key: (input, out1, out2).
    Representative = shortest (then lexicographically smallest) sequence.
    """
    groups = {}
    for d in ds:
        key = (d["input"], d["out1"], d["out2"]) if coarse else \
              (d["input"], d["out1"], d["out2"], d["state1"], d["state2"])
        groups.setdefault(key, []).append(d)
    classes = []
    for key, members in groups.items():
        members = sorted(members, key=lambda d: (len(_seq(d)), _seq(d), d["state1"], d["state2"]))
        rep = members[0]
        c = {"input": rep["input"], "out1": rep["out1"], "out2": rep["out2"],
             "sequence": _seq(rep), "trace1": rep["trace1"], "trace2": rep["trace2"],
             "member_count": len(members),
             "examples": [_seq(m) for m in members[1:1 + n_examples]]}
        if coarse:
            c["n_state_pairs"] = len({(m["state1"], m["state2"]) for m in members})
        else:
            c["state1"], c["state2"] = rep["state1"], rep["state2"]
        classes.append(c)
    classes.sort(key=lambda c: (len(c["sequence"]), c["sequence"], c["out1"], c["out2"],
                                c.get("state1", ""), c.get("state2", "")))
    return classes


def normalize_machine(m, mapping):
    for s in m.states:
        for i, o in list(s.output_fun.items()):
            s.output_fun[i] = mapping.get(o, o)
    return m


def diff_models(m1, m2, names, normalize=None):
    rep = alphabet_report(m1, m2)
    ds = distinguishing_sequences(m1, m2)
    return {"names": list(names),
            "alphabets": {names[0]: rep["alphabet1"], names[1]: rep["alphabet2"]},
            "alphabets_identical": rep["identical"],
            "alphabet_only_in": {names[0]: rep["only_in_1"], names[1]: rep["only_in_2"]},
            "diffed_inputs": rep["common"],
            "n_states": [len(m1.states), len(m2.states)],
            "equivalent": rep["identical"] and not ds,
            "equivalent_on_common_inputs": not ds,
            "normalize": normalize,
            "n_disagreements": len(ds),
            "classes": group_disagreements(ds),
            "coarse_classes": group_disagreements(ds, coarse=True)}


def majority_view(models, names, pair_results):
    """For each representative sequence of any pairwise class, show what every server outputs."""
    seqs = {}
    for r in pair_results.values():
        for c in r["classes"]:
            seqs[tuple(c["sequence"])] = True
    view = []
    for seq in sorted(seqs, key=lambda s: (len(s), s)):
        outs = {}
        for n, m in zip(names, models):
            tr = run_trace(m, seq)
            outs[n] = tr[-1] if len(tr) == len(seq) else UNDEF
        groups = {}
        for n in names:
            groups.setdefault(outs[n], []).append(n)
        top = max(groups.values(), key=len)
        unique_top = sum(1 for g in groups.values() if len(g) == len(top)) == 1
        maj = next(o for o, g in groups.items() if g is top) if unique_top else None
        view.append({"sequence": list(seq), "outputs": outs,
                     "groups": groups, "majority_output": maj,
                     "outliers": sorted(n for o, g in groups.items() if maj is not None and o != maj for n in g)})
    return view


def _summary(r):
    a, b = r["names"]
    lines = [f"{a} ({r['n_states'][0]} states) vs {b} ({r['n_states'][1]} states): "
             + ("EQUIVALENT" if r["equivalent"] else f"{r['n_disagreements']} disagreements, "
                f"{len(r['classes'])} classes, {len(r['coarse_classes'])} coarse")]
    if not r["alphabets_identical"]:
        lines.append(f"  alphabets differ; only in {a}: {r['alphabet_only_in'][a]}; only in {b}: {r['alphabet_only_in'][b]}")
    if r["normalize"]:
        lines.append(f"  NOTE: outputs normalized with {r['normalize']['path']}")
    for c in r["coarse_classes"][:10]:
        lines.append(f"  [{c['member_count']}x] {' '.join(c['sequence'])}: {a}={c['out1']} {b}={c['out2']}")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="psm.diff")
    ap.add_argument("models", nargs="+", help="two or more .dot Mealy models")
    ap.add_argument("--out", required=True)
    ap.add_argument("--names", nargs="+")
    ap.add_argument("--normalize", help="JSON map of output symbol -> replacement, applied before diffing")
    a = ap.parse_args(argv)
    if len(a.models) < 2:
        ap.error("need at least two models")
    names = a.names or [os.path.splitext(os.path.basename(p))[0] for p in a.models]
    if len(names) != len(a.models):
        ap.error("--names count must match models")
    models = [load_mealy(p) for p in a.models]
    norm = None
    if a.normalize:
        with open(a.normalize) as f:
            mapping = json.load(f)
        for m in models:
            normalize_machine(m, mapping)
        norm = {"path": a.normalize, "map": mapping}

    pairs = {}
    for (i, n1), (j, n2) in itertools.combinations(list(enumerate(names)), 2):
        pairs[f"{n1}__vs__{n2}"] = diff_models(models[i], models[j], [n1, n2], norm)
    if len(models) == 2:
        result = next(iter(pairs.values()))
    else:
        result = {"names": names, "normalize": norm, "pairs": pairs,
                  "majority": majority_view(models, names, pairs)}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(result, f, indent=2)
    for r in pairs.values():
        print(_summary(r))
    if len(models) > 2:
        print(f"majority view: {len(result['majority'])} sequences")
    print(f"wrote {a.out}")
    return result


if __name__ == "__main__":
    main()
