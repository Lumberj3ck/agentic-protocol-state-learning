import json

import pytest
from aalpy.automata import MealyMachine, MealyState
from aalpy.utils import save_automaton_to_file

from psm import diff as D


def build(spec, init="s0"):
    """spec: {state: {input: (output, next)}}"""
    states = {n: MealyState(n) for n in spec}
    for n, tr in spec.items():
        for i, (o, t) in tr.items():
            states[n].transitions[i] = states[t]
            states[n].output_fun[i] = o
    return MealyMachine(states[init], list(states.values()))


def chain(last_out="X", n=4):
    """a-chain: a advances s0->s1->...->s{n-1} (loops); output 'o' except at end where 'a' gives last_out."""
    spec = {}
    for k in range(n):
        nxt = f"s{min(k + 1, n - 1)}"
        out = last_out if k == n - 1 else "o"
        spec[f"s{k}"] = {"a": (out, nxt), "b": ("o", "s0")}
    return build(spec)


def two_state():
    return build({"s0": {"a": ("1", "s1"), "b": ("0", "s0")},
                  "s1": {"a": ("0", "s0"), "b": ("1", "s1")}})


def test_identical():
    m1, m2 = two_state(), two_state()
    assert D.are_equivalent(m1, m2)
    assert D.distinguishing_sequences(m1, m2) == []
    assert D.group_disagreements(D.distinguishing_sequences(m1, m2)) == []


def test_single_output_difference():
    m1 = two_state()
    m2 = build({"s0": {"a": ("1", "s1"), "b": ("0", "s0")},
                "s1": {"a": ("0", "s0"), "b": ("DIFF", "s1")}})
    assert not D.are_equivalent(m1, m2)
    ds = D.distinguishing_sequences(m1, m2)
    assert len(ds) == 1
    d = ds[0]
    assert d["access"] == ["a"] and d["input"] == "b"
    assert d["out1"] == "1" and d["out2"] == "DIFF"
    assert d["trace1"] == ["1", "1"] and d["trace2"] == ["1", "DIFF"]
    assert d["state1"] == "s1" and d["state2"] == "s1"
    classes = D.group_disagreements(ds)
    assert len(classes) == 1 and classes[0]["sequence"] == ["a", "b"]
    assert classes[0]["member_count"] == 1


def test_minimal_vs_nonminimal_equivalent():
    m1 = two_state()
    # s0/s2 duplicates, s1/s3 duplicates
    m2 = build({"s0": {"a": ("1", "s1"), "b": ("0", "s2")},
                "s1": {"a": ("0", "s2"), "b": ("1", "s3")},
                "s2": {"a": ("1", "s3"), "b": ("0", "s0")},
                "s3": {"a": ("0", "s0"), "b": ("1", "s1")}})
    assert len(m1.states) != len(m2.states)
    assert D.are_equivalent(m1, m2)
    assert D.distinguishing_sequences(m1, m2) == []


def test_deep_divergence_shortest_prefix():
    m1, m2 = chain("X"), chain("Y")
    ds = D.distinguishing_sequences(m1, m2)
    assert ds[0]["access"] == ["a", "a", "a"]
    assert min(len(d["access"]) for d in ds) == 3
    cl = D.group_disagreements(ds)
    assert cl[0]["sequence"] == ["a", "a", "a", "a"]
    assert cl[0]["out1"] == "X" and cl[0]["out2"] == "Y"
    assert cl[0]["trace1"][-1] == "X" and cl[0]["trace2"][-1] == "Y"
    # b from s3 returns to s0 in both: no other differences
    assert len(ds) == 1


def test_many_members_one_class_and_coarse():
    # divergence state reachable via several product states -> same class, more members
    m1 = build({"s0": {"a": ("o", "s1"), "b": ("o", "s2")},
                "s1": {"a": ("X", "s1"), "b": ("o", "s1")},
                "s2": {"a": ("X", "s2"), "b": ("o", "s2")}})
    m2 = build({"s0": {"a": ("o", "s1"), "b": ("o", "s2")},
                "s1": {"a": ("Y", "s1"), "b": ("o", "s1")},
                "s2": {"a": ("Y", "s2"), "b": ("o", "s2")}})
    ds = D.distinguishing_sequences(m1, m2)
    assert len(ds) == 2
    fine = D.group_disagreements(ds)
    assert len(fine) == 2  # different source states
    coarse = D.group_disagreements(ds, coarse=True)
    assert len(coarse) == 1 and coarse[0]["member_count"] == 2
    assert coarse[0]["sequence"] == ["a", "a"]
    assert coarse[0]["examples"] == [["b", "a"]]


def test_no_conn_vs_disconnect_reported_faithfully():
    m1 = build({"s0": {"a": ("DISCONNECT", "s1")}, "s1": {"a": ("NO_CONN", "s1")}})
    m2 = build({"s0": {"a": ("NO_CONN", "s1")}, "s1": {"a": ("NO_CONN", "s1")}})
    ds = D.distinguishing_sequences(m1, m2)
    assert [(d["out1"], d["out2"]) for d in ds] == [("DISCONNECT", "NO_CONN")]


def test_alphabet_mismatch_uses_common_inputs():
    m1 = two_state()
    m2 = build({"s0": {"a": ("1", "s1"), "b": ("0", "s0"), "c": ("Z", "s0")},
                "s1": {"a": ("0", "s0"), "b": ("1", "s1"), "c": ("Z", "s0")}})
    assert D.alphabet_report(m1, m2)["only_in_2"] == ["c"]
    assert D.distinguishing_sequences(m1, m2) == []
    assert not D.are_equivalent(m1, m2)  # alphabets differ
    assert D.are_equivalent(m1, m2, inputs=["a", "b"])


def test_dot_roundtrip(tmp_path):
    m1 = chain("X")
    m2 = chain("Y")
    p1, p2 = tmp_path / "A.dot", tmp_path / "B.dot"
    save_automaton_to_file(m1, str(p1), file_type="dot")
    save_automaton_to_file(m2, str(p2), file_type="dot")
    l1, l2 = D.load_mealy(str(p1)), D.load_mealy(str(p2))
    assert D.group_disagreements(D.distinguishing_sequences(l1, l2)) == \
        D.group_disagreements(D.distinguishing_sequences(m1, m2))


def test_deterministic_ordering():
    m1 = build({"s0": {"a": ("o", "s0"), "b": ("o", "s0"), "c": ("o", "s0")}})
    m2 = build({"s0": {"c": ("3", "s0"), "b": ("2", "s0"), "a": ("1", "s0")}})
    r1 = D.group_disagreements(D.distinguishing_sequences(m1, m2))
    r2 = D.group_disagreements(D.distinguishing_sequences(m2.__class__ and m1, m2))
    assert r1 == r2
    assert [c["input"] for c in r1] == ["a", "b", "c"]


def test_cli_json_and_normalize(tmp_path):
    p1, p2 = tmp_path / "A.dot", tmp_path / "B.dot"
    m1 = build({"s0": {"a": ("DISCONNECT", "s0")}})
    m2 = build({"s0": {"a": ("NO_CONN", "s0")}})
    save_automaton_to_file(m1, str(p1), file_type="dot")
    save_automaton_to_file(m2, str(p2), file_type="dot")
    out = tmp_path / "o" / "r.json"
    D.main([str(p1), str(p2), "--out", str(out), "--names", "x", "y"])
    r = json.loads(out.read_text())
    assert r["names"] == ["x", "y"] and r["equivalent"] is False
    assert r["normalize"] is None and r["n_states"] == [1, 1]
    assert r["classes"][0]["out1"] == "DISCONNECT"
    mp = tmp_path / "map.json"
    mp.write_text(json.dumps({"DISCONNECT": "NO_CONN"}))
    out2 = tmp_path / "r2.json"
    D.main([str(p1), str(p2), "--out", str(out2), "--normalize", str(mp)])
    r2 = json.loads(out2.read_text())
    assert r2["equivalent"] is True and r2["normalize"]["map"] == {"DISCONNECT": "NO_CONN"}


def test_nway(tmp_path):
    ms = {"A": chain("X"), "B": chain("X"), "C": chain("Y")}
    paths = []
    for n, m in ms.items():
        p = tmp_path / f"{n}.dot"
        save_automaton_to_file(m, str(p), file_type="dot")
        paths.append(str(p))
    out = tmp_path / "n.json"
    D.main(paths + ["--out", str(out), "--names", "A", "B", "C"])
    r = json.loads(out.read_text())
    assert len(r["pairs"]) == 3
    assert r["pairs"]["A__vs__B"]["equivalent"] is True
    mv = r["majority"]
    assert len(mv) == 1
    assert mv[0]["majority_output"] == "X" and mv[0]["groups"] == {"X": ["A", "B"], "Y": ["C"]}
    assert mv[0]["outliers"] == ["C"]


def test_restricting_inputs_hides_differences_on_other_inputs():
    from aalpy.automata import MealyMachine, MealyState
    from psm.diff import diff_models

    def mk(out_c):
        s0, s1 = MealyState("s0"), MealyState("s1")
        s0.transitions.update(a=s1, c=s0)
        s0.output_fun.update(a="A", c=out_c)
        s1.transitions.update(a=s1, c=s1)
        s1.output_fun.update(a="A2", c=out_c)
        return MealyMachine(s0, [s0, s1])

    full = diff_models(mk("X"), mk("Y"), ["m1", "m2"])
    assert full["n_disagreements"] >= 1 and not full["equivalent"]
    restricted = diff_models(mk("X"), mk("Y"), ["m1", "m2"], inputs=["a"])
    assert restricted["n_disagreements"] == 0 and restricted["equivalent_on_common_inputs"]
    assert restricted["restricted_to_inputs"] == ["a"] and not restricted["equivalent"]
