"""Offline tests of the SSH conformance catalogue (catalogue/ssh/*.json) on hand-built Mealy models."""

import copy
import re
from pathlib import Path

import pytest
from aalpy.automata import MealyMachine, MealyState

from smlearn.catalogue import check, load_catalogue

ROOT = Path(__file__).resolve().parent.parent
CATALOGUE = ROOT / "catalogue" / "ssh"
SPEC = (ROOT / "docs" / "MAPPER-SPEC-SSH.md").read_text()

# The alphabet as written in the mapper spec: input table rows and the "Message names:" line.
INPUTS = re.findall(r"^\| `([A-Z0-9_]+)` \|", SPEC, re.M)
MESSAGES = re.search(r"^Message names: `([^`]+)`", SPEC, re.M).group(1).split(", ")
SPECIAL = ["NO_RESP", "CLOSED", "NO_CONN", "NO_CHANNEL", "BAD_PACKET"]
TOKENS = set(MESSAGES) | set(SPECIAL)

REQUIRED = {"id", "title", "source", "quote", "level", "rationale", "automaton"}
TRANSITION_KEYS = {"from", "to", "in", "in_not", "out_has", "out_lacks"}

PATTERNS = {p["id"]: p for p in load_catalogue(CATALOGUE)}


def mealy(spec, initial="s0"):
    """spec: {state: {input: (output, next_state)}}"""
    states = {n: MealyState(n) for n in spec}
    for n, row in spec.items():
        for a, (o, nxt) in row.items():
            states[n].transitions[a] = states[nxt]
            states[n].output_fun[a] = o
    return MealyMachine(states[initial], list(states.values()))


# ---------------------------------------------------------------------------
# (a) every catalogue file is well formed and uses only the spec's symbols


def test_spec_alphabet_parsed():
    assert len(INPUTS) == 17 and INPUTS[0] == "KEXINIT" and INPUTS[-1] == "DISCONNECT"
    assert "SERVICE_ACCEPT" in MESSAGES and "CH_FAILURE" in MESSAGES


def test_catalogue_size():
    assert 8 <= len(list(CATALOGUE.glob("*.json"))) <= 15
    assert len(PATTERNS) == len(list(CATALOGUE.glob("*.json"))), "duplicate ids"


@pytest.mark.parametrize("pid", sorted(PATTERNS))
def test_pattern_well_formed(pid):
    p = PATTERNS[pid]
    assert REQUIRED <= p.keys()
    assert p["file"] == f"{pid}.json"
    assert p["level"] in ("MUST", "SHOULD")
    for k in ("title", "source", "quote", "rationale"):
        assert isinstance(p[k], str) and p[k].strip()
    a = p["automaton"]
    assert set(a) == {"initial", "accept", "transitions"}
    assert a["accept"] and a["transitions"]
    states = {a["initial"], *a["accept"]}
    for t in a["transitions"]:
        assert t.keys() <= TRANSITION_KEYS and {"from", "to"} <= t.keys(), t
        states |= {t["from"], t["to"]}
        ins = t.get("in", [])
        for sym in (ins if isinstance(ins, list) else [ins]) + t.get("in_not", []):
            assert sym in INPUTS, f"{pid}: unknown input {sym}"
        for tok in t.get("out_has", []) + t.get("out_lacks", []):
            assert tok in TOKENS, f"{pid}: unknown output token {tok}"
    # Every accepting state is the target of some transition.
    assert set(a["accept"]) <= {t["to"] for t in a["transitions"]}


# ---------------------------------------------------------------------------
# (b) a conforming reference server and single-defect mutants

CHAN = ("CH_CLOSE", "CH_EOF", "CH_DATA", "CH_REQUEST_EXEC")
FATAL = "DISCONNECT+CLOSED"


def reference():
    """A small server model that conforms to every catalogue entry.

    s0: server KEXINIT absorbed; bad0: first packet was not KEXINIT (checked retrospectively);
    ki: client KEXINIT sent; kr: server NEWKEYS sent; post: KEX done; auth: ssh-userauth running;
    conn: authenticated; chan: channel open; rk1_X / rk2_X: re-exchange started from X.
    Returns {state: {input: (output, next_state)}}.
    """
    spec = {"dead": {a: ("NO_CONN", "dead") for a in INPUTS}}

    def state(name, default, **over):
        # A next state of None means "stay here".
        row = {a: default for a in INPUTS}
        row.update({a: ("NO_CHANNEL", None) for a in CHAN})
        row["DISCONNECT"] = ("CLOSED", "dead")
        row.update(over)
        spec[name] = {a: (o, name if n is None else n) for a, (o, n) in row.items()}

    dead = (FATAL, "dead")
    state("s0", ("NO_RESP", "bad0"), KEXINIT=("NO_RESP", "ki"), KEX30=dead, NEWKEYS=dead)
    state("bad0", ("NO_RESP", None), KEXINIT=dead)
    state("ki", dead, KEX30=("KEX31+NEWKEYS", "kr"))
    state("kr", dead, NEWKEYS=("NO_RESP", "post"))

    quiet = ("NO_RESP", None)
    after_kex = {"IGNORE": quiet, "DEBUG": quiet, "UNIMPLEMENTED": quiet,
                 "KEX30": dead, "NEWKEYS": dead, "SR_CONN": dead, "CH_OPEN": dead}
    rows = {
        "post": {**after_kex, "SR_AUTH": ("SERVICE_ACCEPT", "auth")},
        "auth": {**after_kex, "UA_PW_OK": ("UA_SUCCESS", "conn"),
                 "UA_PW_NOK": ("UA_FAILURE", None), "UA_NONE": ("UA_FAILURE", None)},
        "conn": {**after_kex, "SR_AUTH": ("UNIMPLEMENTED", None), "SR_CONN": ("UNIMPLEMENTED", None),
                 "UA_PW_OK": quiet, "UA_PW_NOK": quiet, "UA_NONE": quiet,
                 "CH_OPEN": ("CH_OPEN_SUCCESS", "chan")},
    }
    rows["chan"] = {**rows["conn"], "CH_DATA": quiet, "CH_EOF": quiet, "CH_CLOSE": ("CH_CLOSE", "conn"),
                    "CH_REQUEST_EXEC": ("CH_SUCCESS+CH_REQUEST+CH_EOF+CH_CLOSE", "conn")}
    for x, over in rows.items():
        state(x, ("UNIMPLEMENTED", None), **over, KEXINIT=("KEXINIT", f"rk1_{x}"))
        chan = {a: quiet for a in CHAN} if x == "chan" else {}
        state(f"rk1_{x}", dead, IGNORE=quiet, DEBUG=quiet, **chan, KEX30=("KEX31+NEWKEYS", f"rk2_{x}"))
        state(f"rk2_{x}", dead, IGNORE=quiet, DEBUG=quiet, **chan, NEWKEYS=("NO_RESP", x))
    return spec


def mutant(*changes):
    spec = copy.deepcopy(reference())
    for state, inp, out, nxt in changes:
        spec[state][inp] = (out, nxt)
    return mealy(spec)


REF = mealy(reference())


def word(w):
    return [s["in"] for s in w]


@pytest.mark.parametrize("pid", sorted(PATTERNS))
def test_reference_server_conforms(pid):
    assert check(REF, PATTERNS[pid]) is None


def test_reference_happy_path():
    outs = []
    s = REF.initial_state
    for a in ["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "UA_PW_NOK", "UA_PW_OK", "CH_OPEN",
              "CH_REQUEST_EXEC"]:
        outs.append(s.output_fun[a])
        s = s.transitions[a]
    assert outs == ["NO_RESP", "KEX31+NEWKEYS", "NO_RESP", "SERVICE_ACCEPT", "UA_FAILURE",
                    "UA_SUCCESS", "CH_OPEN_SUCCESS", "CH_SUCCESS+CH_REQUEST+CH_EOF+CH_CLOSE"]


# name: (all pattern ids the mutant violates, first one checked for its witness,
#        [(state, input, new output, new next state)],
#        expected witness inputs | last witness input | None for "some witness")
KEX = ["KEXINIT", "KEX30", "NEWKEYS"]
CASES = {
    "ignore-during-strict-kex": (
        ["STRICT-KEX-NON-KEX-MSG"], [("ki", "IGNORE", "NO_RESP", "ki")],
        ["KEXINIT", "IGNORE", "KEX30", "NEWKEYS", "KEXINIT"]),
    "debug-after-server-newkeys": (
        ["STRICT-KEX-NON-KEX-MSG"], [("kr", "DEBUG", "NO_RESP", "kr")],
        ["KEXINIT", "KEX30", "DEBUG", "NEWKEYS", "KEXINIT"]),
    "kexinit-not-first": (
        ["STRICT-KEX-FIRST-KEXINIT"], [("bad0", "KEXINIT", "NO_RESP", "ki")], "KEXINIT"),
    "second-kex30": (
        ["STRICT-KEX-REPEATED-MSG"], [("kr", "KEX30", "KEX31+NEWKEYS", "kr")],
        ["KEXINIT", "KEX30", "KEX30"]),
    "service-before-kex": (
        # Staying in s0 also means the later KEXINIT is accepted although it was not first.
        ["KEX-SERVER-SENDS-NON-KEX", "SR-ACCEPT-BEFORE-NEWKEYS", "STRICT-KEX-FIRST-KEXINIT"],
        [("s0", "SR_AUTH", "SERVICE_ACCEPT", "s0")], ["SR_AUTH"]),
    "service-before-client-newkeys": (
        ["SR-ACCEPT-BEFORE-NEWKEYS", "STRICT-KEX-NON-KEX-MSG"],
        [("kr", "SR_AUTH", "SERVICE_ACCEPT", "kr")], ["KEXINIT", "KEX30", "SR_AUTH"]),
    "rekey-ignored": (
        ["REKEY-KEXINIT-REPLY"], [("post", "KEXINIT", "NO_RESP", "post")], KEX + ["KEXINIT"]),
    "rekey-drops-connection": (
        ["REKEY-KEXINIT-REPLY"], [("conn", "KEXINIT", FATAL, "dead")], None),
    "duplicate-kexinit": (
        # Also tolerates the client's second KEXINIT, which strict KEX forbids.
        ["KEXINIT-DUPLICATE", "STRICT-KEX-REPEATED-MSG"], [("ki", "KEXINIT", "KEXINIT", "ki")],
        ["KEXINIT", "KEXINIT"]),
    "ignore-rejected-after-kex": (
        ["IGNORE-DEBUG-TOLERATED"], [("auth", "IGNORE", FATAL, "dead")], KEX + ["SR_AUTH", "IGNORE"]),
    "talks-after-own-disconnect": (
        ["SEND-AFTER-DISCONNECT"], [("post", "SR_CONN", "DISCONNECT", "post")], None),
    "accepts-after-client-disconnect": (
        ["RECV-AFTER-DISCONNECT"], [("auth", "DISCONNECT", "NO_RESP", "auth")], None),
    "userauth-without-service-request": (
        ["UA-BEFORE-SR-AUTH"], [("post", "UA_PW_NOK", "UA_FAILURE", "post")], KEX + ["UA_PW_NOK"]),
    "channel-open-failure-before-auth": (
        ["CONN-BEFORE-AUTH"], [("auth", "CH_OPEN", "CH_OPEN_FAILURE", "auth")],
        KEX + ["SR_AUTH", "CH_OPEN"]),
    "ssh-connection-before-auth": (
        ["CONN-BEFORE-AUTH"], [("auth", "SR_CONN", "SERVICE_ACCEPT", "auth")],
        KEX + ["SR_AUTH", "SR_CONN"]),
    "unauthenticated-channel": (
        ["UNAUTH-CHANNEL-OPEN", "CONN-BEFORE-AUTH"], [("auth", "CH_OPEN", "CH_OPEN_SUCCESS", "chan")],
        KEX + ["SR_AUTH", "CH_OPEN"]),
    "none-accepted": (
        ["AUTH-WITHOUT-CREDENTIALS"], [("auth", "UA_NONE", "UA_SUCCESS", "conn")],
        KEX + ["SR_AUTH", "UA_NONE"]),
    "channel-close-unanswered": (
        ["CH-CLOSE-REPLY"], [("chan", "CH_CLOSE", "NO_RESP", "conn")], None),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_mutant_violates_exactly_expected(case):
    expected, changes, w = CASES[case]
    m = mutant(*changes)
    violated = {pid for pid, p in PATTERNS.items() if check(m, p) is not None}
    assert violated == set(expected)
    witness = check(m, PATTERNS[expected[0]])
    if isinstance(w, list):
        assert word(witness) == w
    elif isinstance(w, str):
        assert witness[-1]["in"] == w


def test_auth_success_after_wrong_password_failure():
    # Failing once with a wrong password puts the server in a state that accepts "none".
    spec = reference()
    spec["auth2"] = dict(spec["auth"], UA_NONE=("UA_SUCCESS", "conn"))
    spec["auth"] = dict(spec["auth"], UA_PW_NOK=("UA_FAILURE", "auth2"))
    w = check(mealy(spec), PATTERNS["AUTH-WITHOUT-CREDENTIALS"])
    assert w == [{"in": "KEXINIT", "out": "NO_RESP"}, {"in": "KEX30", "out": "KEX31+NEWKEYS"},
                 {"in": "NEWKEYS", "out": "NO_RESP"}, {"in": "SR_AUTH", "out": "SERVICE_ACCEPT"},
                 {"in": "UA_PW_NOK", "out": "UA_FAILURE"}, {"in": "UA_NONE", "out": "UA_SUCCESS"}]


def test_correct_password_after_failure_is_fine():
    # Rejected wrong password followed by the right one is the normal flow, not a violation.
    assert check(REF, PATTERNS["AUTH-WITHOUT-CREDENTIALS"]) is None
    assert REF.compute_output_seq(REF.initial_state, KEX + ["SR_AUTH", "UA_PW_NOK", "UA_PW_OK"])[-1] \
        == "UA_SUCCESS"


def test_send_after_disconnect_witness():
    m = mutant(("post", "SR_CONN", "DISCONNECT", "post"))
    w = check(m, PATTERNS["SEND-AFTER-DISCONNECT"])
    assert w[-2] == {"in": "SR_CONN", "out": "DISCONNECT"}
    # Disconnect followed by close in the same step is the conforming behaviour.
    assert check(REF, PATTERNS["SEND-AFTER-DISCONNECT"]) is None


def test_strict_kex_small_models():
    # Four-input models in the style of tests/test_analysis.py: a strict server closes on IGNORE
    # anywhere in the initial KEX (and on KEXINIT after a stray first packet); a lax one ignores it.
    def model(ignore_in_kex, kexinit_after_stray):
        return mealy({
            "s0": {"KEXINIT": ("NO_RESP", "s1"), "IGNORE": ("NO_RESP", "x"), "KEX30": (FATAL, "d"), "NEWKEYS": (FATAL, "d")},
            "x": {"KEXINIT": kexinit_after_stray, "IGNORE": ("NO_RESP", "x"), "KEX30": (FATAL, "d"), "NEWKEYS": (FATAL, "d")},
            "s1": {"KEXINIT": (FATAL, "d"), "IGNORE": ignore_in_kex("s1"), "KEX30": ("KEX31+NEWKEYS", "s2"), "NEWKEYS": (FATAL, "d")},
            "s2": {"KEXINIT": (FATAL, "d"), "IGNORE": ignore_in_kex("s2"), "KEX30": (FATAL, "d"), "NEWKEYS": ("NO_RESP", "s3")},
            "s3": {"KEXINIT": ("KEXINIT", "s3"), "IGNORE": ("NO_RESP", "s3"), "KEX30": (FATAL, "d"), "NEWKEYS": (FATAL, "d")},
            "d": {a: ("NO_CONN", "d") for a in ("KEXINIT", "IGNORE", "KEX30", "NEWKEYS")},
        })

    strict = model(lambda s: ("CLOSED", "d"), (FATAL, "d"))
    lax = model(lambda s: ("NO_RESP", s), ("NO_RESP", "s1"))
    for pid in ("STRICT-KEX-NON-KEX-MSG", "STRICT-KEX-FIRST-KEXINIT", "IGNORE-DEBUG-TOLERATED"):
        assert check(strict, PATTERNS[pid]) is None
    assert word(check(lax, PATTERNS["STRICT-KEX-NON-KEX-MSG"])) == ["KEXINIT", "IGNORE", "KEX30", "NEWKEYS", "KEXINIT"]
    assert word(check(lax, PATTERNS["STRICT-KEX-FIRST-KEXINIT"])) == ["IGNORE", "KEXINIT", "KEX30", "NEWKEYS", "KEXINIT"]
    assert check(lax, PATTERNS["IGNORE-DEBUG-TOLERATED"]) is None


def test_strict_kex_deferred_termination_conforms():
    # libssh 0.12.2 (results/seqnr/libssh-strict-kex-debug.txt): silent on DEBUG during the initial KEX,
    # then DISCONNECT at the client NEWKEYS. The draft allows the deferred termination.
    spec = copy.deepcopy(reference())
    spec["ki"]["DEBUG"] = ("NO_RESP", "ki_dbg")
    spec["ki_dbg"] = {a: (FATAL, "dead") for a in spec["ki"]}
    spec["ki_dbg"]["KEX30"] = ("KEX31+NEWKEYS", "kr_dbg")
    spec["kr_dbg"] = {a: (FATAL, "dead") for a in spec["kr"]}
    spec["kr_dbg"]["NEWKEYS"] = ("DISCONNECT+CLOSED", "dead")
    assert check(mealy(spec), PATTERNS["STRICT-KEX-NON-KEX-MSG"]) is None
