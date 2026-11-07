from aalpy.automata import MealyMachine, MealyState

from psm import xharness as X


def build(spec, init="s0"):
    states = {n: MealyState(n) for n in spec}
    for n, tr in spec.items():
        for i, (o, t) in tr.items():
            states[n].transitions[i] = states[t]
            states[n].output_fun[i] = o
    return MealyMachine(states[init], list(states.values()))


def test_output_maps():
    assert X.map_theirs_output("CLOSED") == "NO_CONN"
    assert X.map_theirs_output("DISCONNECT+CLOSED") == "DISCONNECT"
    assert X.map_theirs_output("UNIMPLEMENTED") == "UNIMPL"
    assert X.map_theirs_output("SERVICE_ACCEPT") == "SR_ACCEPT"
    assert X.map_theirs_output("IGNORE") == "NO_RESP"
    assert X.map_theirs_output("UA_SUCCESS+GLOBAL_REQUEST") == "UA_SUCCESS"
    assert X.map_ours_output("KEXINIT", first_step=True) == "NO_RESP"
    assert X.map_ours_output("KEXINIT+UNIMPL", first_step=True) == "UNIMPL"
    assert X.map_ours_output("KEXINIT", first_step=False) == "KEXINIT"
    assert X.map_ours_output("KEX31+NEWKEYS+EXT_INFO") == "KEX31+NEWKEYS"
    assert X.ours_output_to_theirs("UNIMPL") == "UNIMPLEMENTED"
    assert X.ours_output_to_theirs("KEXINIT", first_step=True) == "NO_RESP"


def ours_toy():
    # s0 is re-entered by 'b': only the FIRST step's KEXINIT may be stripped
    return build({"s0": {"KEXINIT": ("KEXINIT", "s1"), "UA_PK_OK": ("KEXINIT", "s0")},
                  "s1": {"KEXINIT": ("NO_CONN", "s1"), "UA_PK_OK": ("UNIMPL", "s0")}})


def test_initial_split_only_first_step():
    c = X.ours_to_common(ours_toy())
    assert c.execute_sequence(c.initial_state, ["KEXINIT", "UA_PK_OK", "KEXINIT"]) == ["NO_RESP", "UNIMPL", "KEXINIT"]


def test_xdiff_equivalent_after_mapping():
    theirs = build({"t0": {"KEXINIT": ("NO_RESP", "t1"), "UA_PW_OK": ("NO_RESP", "t0")},
                    "t1": {"KEXINIT": ("CLOSED", "t2"), "UA_PW_OK": ("UNIMPLEMENTED", "t3")},
                    "t2": {"KEXINIT": ("NO_CONN", "t2"), "UA_PW_OK": ("NO_CONN", "t2")},
                    "t3": {"KEXINIT": ("KEXINIT", "t1"), "UA_PW_OK": ("NO_RESP", "t3")}}, init="t0")
    r = X.xdiff(ours_toy(), theirs)
    assert r["inputs"] == ["KEXINIT", "UA_PK_OK"]
    # ours: s0 -UA-> s0 (KEXINIT output, not first step) vs theirs t3 -KEXINIT-> KEXINIT ... check one real diff exists
    seqs = [c["sequence"] for c in r["classes"]]
    assert ["KEXINIT", "KEXINIT", "KEXINIT"] not in seqs  # NO_CONN sink agrees with CLOSED->NO_CONN
    assert all(c["comparable"] for c in r["classes"])


def test_xdiff_flags():
    ours = build({"s0": {"KEXINIT": ("KEXINIT", "s0"), "CH_OPEN": ("CH_MAX", "s0")}})
    theirs = build({"t0": {"KEXINIT": ("NO_RESP", "t1"), "CH_OPEN": ("UNIMPLEMENTED", "t0")},
                    "t1": {"KEXINIT": ("KEXINIT", "t1"), "CH_OPEN": ("CH_OPEN_SUCCESS", "t1")}}, init="t0")
    r = X.xdiff(ours, theirs)
    by = {tuple(c["sequence"]): c for c in r["classes"]}
    assert by[("CH_OPEN",)]["auto_kexinit"] is True
    assert by[("KEXINIT", "CH_OPEN")]["comparable"] is False


def test_to_theirs_roundtrip_inputs():
    t = X.ours_to_theirs(ours_toy())
    assert sorted(t.get_input_alphabet()) == ["KEXINIT", "UA_PW_OK"]
    assert t.execute_sequence(t.initial_state, ["KEXINIT", "UA_PW_OK"]) == ["NO_RESP", "UNIMPLEMENTED"]
