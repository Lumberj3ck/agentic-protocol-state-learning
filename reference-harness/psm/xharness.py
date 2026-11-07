"""Cross-harness comparison (stream A, v2): map our ssh-fuzzer-mapper models and the teammate's smlearn-mapper models
into one common vocabulary (results/v2/A/alphabet_map.json, version A-1), then diff them with psm.diff.

Common vocabulary = ours (UNIMPL, SR_ACCEPT, NO_CONN, inputs UA_PK_OK), with:
  - EXT_INFO, IGNORE, DEBUG dropped on both sides; UA_SUCCESS+GLOBAL_REQUEST -> UA_SUCCESS;
  - theirs: CLOSED alone -> NO_CONN, X+CLOSED -> X; UA_PW_OK -> UA_PK_OK;
  - ours: the leading server KEXINIT of the FIRST step is removed (theirs absorbs it in reset()).
    Done by splitting the initial state, so later visits to it are unaffected.
And the other direction (to_theirs) for running the teammate's catalogue on our models.

  python -m psm.xharness diff OURS.dot THEIRS.dot --out results/v2/A/diff_x.json [--inputs ...]
  python -m psm.xharness to-theirs OURS.dot --out converted.dot
"""
from __future__ import annotations

import argparse
import json
import os

from aalpy.automata import MealyMachine, MealyState

DROP = {"EXT_INFO", "IGNORE", "DEBUG"}
T2O_TOK = {"UNIMPLEMENTED": "UNIMPL", "SERVICE_ACCEPT": "SR_ACCEPT"}
O2T_TOK = {v: k for k, v in T2O_TOK.items()}
T2O_IN = {"UA_PW_OK": "UA_PK_OK"}
O2T_IN = {v: k for k, v in T2O_IN.items()}
NOT_COMPARABLE = {"CH_MAX", "NO_CHANNEL", "BAD_PACKET"}


def _fix(s):
    return "UA_SUCCESS" if s == "UA_SUCCESS+GLOBAL_REQUEST" else s


def map_theirs_output(o: str) -> str:
    toks = [T2O_TOK.get(t, t) for t in o.split("+") if t not in DROP]
    if toks == ["CLOSED"]:
        return "NO_CONN"
    toks = [t for t in toks if t != "CLOSED"]
    return _fix("+".join(toks) if toks else "NO_RESP")


def map_ours_output(o: str, first_step: bool = False) -> str:
    toks = [t for t in o.split("+") if t not in DROP]
    if first_step and toks and toks[0] == "KEXINIT":
        toks = toks[1:]
    return _fix("+".join(toks) if toks else "NO_RESP")


def ours_output_to_theirs(o: str, first_step: bool = False) -> str:
    """For the catalogue: our symbol -> their vocabulary. NO_CONN stays NO_CONN (their patterns treat both
    NO_CONN and CLOSED as 'connection gone'); EXT_INFO is kept (their patterns never test it)."""
    toks = o.split("+")
    if first_step and toks and toks[0] == "KEXINIT":
        toks = toks[1:]
    toks = [O2T_TOK.get(t, t) for t in toks]
    return "+".join(toks) if toks else "NO_RESP"


def _rebuild(m, in_map, out_fn, split_initial):
    """Copy machine m renaming inputs and mapping outputs; out_fn(o, first_step)."""
    new = {s: MealyState(str(s.state_id)) for s in m.states}
    for s in m.states:
        for i, o in s.output_fun.items():
            j = in_map.get(i, i)
            new[s].transitions[j] = new[s.transitions[i]]
            new[s].output_fun[j] = out_fn(o, False)
    states = list(new.values())
    init = new[m.initial_state]
    if split_initial:
        s0 = m.initial_state
        init = MealyState(f"{s0.state_id}_init")
        for i, o in s0.output_fun.items():
            j = in_map.get(i, i)
            init.transitions[j] = new[s0.transitions[i]]
            init.output_fun[j] = out_fn(o, True)
        states = [init] + states
    return MealyMachine(init, states)


def ours_to_common(m):
    return _rebuild(m, {}, map_ours_output, split_initial=True)


def theirs_to_common(m):
    return _rebuild(m, T2O_IN, lambda o, first: map_theirs_output(o), split_initial=False)


def ours_to_theirs(m):
    return _rebuild(m, O2T_IN, ours_output_to_theirs, split_initial=True)


def xdiff(ours, theirs, inputs=None):
    """Diff our model against theirs in the common vocabulary. Returns psm.diff-style result plus, per class,
    a 'comparable' flag (False if either output is a mapper-made symbol) and 'auto_kexinit' (first input not KEXINIT)."""
    from psm import diff as D
    a, b = ours_to_common(ours), theirs_to_common(theirs)
    common = sorted(set(D._alphabet(a)) & set(D._alphabet(b)))
    inputs = sorted(inputs) if inputs else common
    ds = D.distinguishing_sequences(a, b, inputs=inputs)
    classes = D.group_disagreements(ds, coarse=True)
    for c in classes:
        toks = set(c["out1"].split("+")) | set(c["out2"].split("+"))
        c["comparable"] = not (toks & NOT_COMPARABLE)
        c["auto_kexinit"] = c["sequence"][0] != "KEXINIT"
    return {"inputs": inputs, "n_states": [len(ours.states), len(theirs.states)],
            "n_disagreements": len(ds), "fine_classes": len(D.group_disagreements(ds)),
            "classes": classes, "disagreements": ds}


def product_size(ours, theirs, inputs):
    """Number of reachable (state pair) and transitions compared in the agreeing product (for rates)."""
    from collections import deque
    a, b = ours_to_common(ours), theirs_to_common(theirs)
    seen = {(a.initial_state, b.initial_state)}
    q = deque(seen)
    trans = agree = 0
    while q:
        s1, s2 = q.popleft()
        for i in inputs:
            trans += 1
            if s1.output_fun[i] != s2.output_fun[i]:
                continue
            agree += 1
            n = (s1.transitions[i], s2.transitions[i])
            if n not in seen:
                seen.add(n)
                q.append(n)
    return {"reachable_state_pairs": len(seen), "transitions_compared": trans, "transitions_agree": agree}


def main(argv=None):
    from psm.diff import load_mealy
    from aalpy.utils import save_automaton_to_file
    ap = argparse.ArgumentParser(prog="psm.xharness")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("diff")
    d.add_argument("ours")
    d.add_argument("theirs")
    d.add_argument("--inputs")
    d.add_argument("--out", required=True)
    t = sub.add_parser("to-theirs")
    t.add_argument("ours")
    t.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    if a.cmd == "to-theirs":
        save_automaton_to_file(ours_to_theirs(load_mealy(a.ours)), a.out.removesuffix(".dot"), file_type="dot")
        return
    o, th = load_mealy(a.ours), load_mealy(a.theirs)
    r = xdiff(o, th, a.inputs.split(",") if a.inputs else None)
    r.update(product_size(o, th, r["inputs"]))
    r["ours"], r["theirs"] = a.ours, a.theirs
    with open(a.out, "w") as f:
        json.dump(r, f, indent=1)
    print(f"{a.ours} vs {a.theirs}: {len(r['classes'])} coarse classes, {r['n_disagreements']} disagreements, "
          f"{r['transitions_agree']}/{r['transitions_compared']} transitions agree")
    for c in r["classes"]:
        print(f"  {' '.join(c['sequence'])}: ours={c['out1']} theirs={c['out2']} "
              f"{'' if c['comparable'] else '[not comparable]'}{'[auto-KEXINIT]' if c['auto_kexinit'] else ''}")


if __name__ == "__main__":
    main()
