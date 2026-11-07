"""Offline tests of differential analysis and the bug-pattern checker on hand-built models."""

from aalpy.automata import MealyMachine, MealyState

from smlearn.catalogue import check
from smlearn.diff import coarse, disagreements


def mealy(spec, initial="s0"):
    """spec: {state: {input: (output, next_state)}}"""
    states = {n: MealyState(n) for n in spec}
    for n, row in spec.items():
        for a, (o, nxt) in row.items():
            states[n].transitions[a] = states[nxt]
            states[n].output_fun[a] = o
    return MealyMachine(states[initial], list(states.values()))


# A strict server closes on IGNORE during the initial key exchange; a lax one ignores it.
STRICT = mealy({
    "s0": {"KEX30": ("KEX31+NEWKEYS", "s1"), "IGNORE": ("CLOSED", "dead"), "NEWKEYS": ("NO_RESP", "s0")},
    "s1": {"KEX30": ("CLOSED", "dead"), "IGNORE": ("CLOSED", "dead"), "NEWKEYS": ("NO_RESP", "s2")},
    "s2": {"KEX30": ("CLOSED", "dead"), "IGNORE": ("NO_RESP", "s2"), "NEWKEYS": ("CLOSED", "dead")},
    "dead": {a: ("NO_CONN", "dead") for a in ("KEX30", "IGNORE", "NEWKEYS")},
})
LAX = mealy({
    "s0": {"KEX30": ("KEX31+NEWKEYS", "s1"), "IGNORE": ("NO_RESP", "s0"), "NEWKEYS": ("NO_RESP", "s0")},
    "s1": {"KEX30": ("CLOSED", "dead"), "IGNORE": ("NO_RESP", "s1"), "NEWKEYS": ("NO_RESP", "s2")},
    "s2": {"KEX30": ("CLOSED", "dead"), "IGNORE": ("NO_RESP", "s2"), "NEWKEYS": ("DISCONNECT+CLOSED", "dead")},
    "dead": {a: ("NO_CONN", "dead") for a in ("KEX30", "IGNORE", "NEWKEYS")},
})

IGNORE_DURING_KEX = {
    "id": "TEST-IGNORE-DURING-KEX",
    "automaton": {
        "initial": "kex", "accept": ["bug"],
        "transitions": [
            {"from": "kex", "to": "kex", "in_not": ["NEWKEYS", "IGNORE"], "out_lacks": ["CLOSED", "NO_CONN"]},
            {"from": "kex", "to": "bug", "in": "IGNORE", "out_lacks": ["CLOSED", "NO_CONN"]},
        ],
    },
}


def test_identical_models_agree():
    assert disagreements(STRICT, STRICT) == []


def test_disagreements_have_shortest_witnesses():
    d = disagreements(STRICT, LAX)
    words = [g["word"] for g in d]
    assert ["IGNORE"] in words
    assert ["KEX30", "NEWKEYS", "NEWKEYS"] in words
    # Same (input, output, output) as ["IGNORE"]: grouped under the shorter witness.
    assert ["KEX30", "IGNORE"] not in words
    assert next(g for g in d if g["word"] == ["IGNORE"])["occurrences"] == 2


def test_coarse_ignores_how_connection_closes():
    assert coarse("DISCONNECT+CLOSED") == coarse("CLOSED") == coarse("NO_CONN")
    words = [g["word"] for g in disagreements(STRICT, LAX, normalize=coarse)]
    assert ["KEX30", "NEWKEYS", "NEWKEYS"] not in words
    assert ["IGNORE"] in words


def test_pattern_finds_lax_but_not_strict():
    assert check(STRICT, IGNORE_DURING_KEX) is None
    w = check(LAX, IGNORE_DURING_KEX)
    assert w == [{"in": "IGNORE", "out": "NO_RESP"}]


def test_eq_oracle_covers_seed_paths_depth_one():
    from smlearn.learn import ParallelEqOracle
    alphabet = ["KEX30", "IGNORE", "NEWKEYS"]
    eq = ParallelEqOracle(alphabet, sul=None, pool=[None], log=None,
                          walks_per_state=2, max_suffix=2, seed_paths=[["KEX30", "NEWKEYS", "SR_AUTH"]])
    STRICT.compute_prefixes()
    words = eq._words(STRICT)
    # SR_AUTH is not in the alphabet, so the seed path is cut to KEX30 NEWKEYS.
    for prefix in [(), ("KEX30",), ("KEX30", "NEWKEYS")]:
        for a in alphabet:
            assert prefix + (a,) in words
    assert words == sorted(words, key=lambda w: (len(w), w))
