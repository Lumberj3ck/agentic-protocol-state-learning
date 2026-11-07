"""Tests for replay (evidence logging) and check_traces (model vs replayed traces)."""
import json

from aalpy.utils import save_automaton_to_file

from psm import check_traces, replay
from tests.test_sul import FakeMapper, toy_machine


def test_replay_logs_observations_and_detects_disagreement():
    a = FakeMapper(toy_machine())
    b_machine = toy_machine()
    b_machine.states[2].output_fun["b"] = "NO_RESP"  # s2 answers b differently
    b = FakeMapper(b_machine)
    res = replay.replay({"a": (a.port, ""), "b": (b.port, "")}, [["a", "b", "b"], ["b"]], reps=3)
    first, second = res["sequences"]
    assert first["results"]["a"]["observations"] == [["KEXINIT", "KEX31+NEWKEYS", "UNIMPL"]] * 3
    assert first["results"]["b"]["distinct"] == [{"outputs": ["KEXINIT", "KEX31+NEWKEYS", "NO_RESP"], "count": 3}]
    assert first["targets_disagree"] and first["all_deterministic"]
    assert not second["targets_disagree"]


def test_replay_flags_nondeterminism():
    a = FakeMapper(toy_machine(), flaky=0.5, seed=1)
    res = replay.replay({"a": (a.port, "")}, [["a", "b"]], reps=12)
    r = res["sequences"][0]["results"]["a"]
    assert not r["deterministic"] and len(r["distinct"]) == 2
    assert not res["sequences"][0]["targets_disagree"]  # nondeterministic results never count as a disagreement


def test_check_traces_reports_mismatch(tmp_path, capsys, monkeypatch):
    save_automaton_to_file(toy_machine(), str(tmp_path / "m"), file_type="dot")
    rep = {"sequences": [
        {"sequence": ["a", "b"], "results": {"x": {"distinct": [{"outputs": ["KEXINIT", "KEX31+NEWKEYS"], "count": 1}]}}},
        {"sequence": ["a", "a"], "results": {"x": {"distinct": [{"outputs": ["KEXINIT", "UNIMPL"], "count": 1}]}}},
        {"sequence": ["z"], "results": {"x": {"distinct": [{"outputs": ["NO_RESP"], "count": 1}]}}},
    ]}
    (tmp_path / "r.json").write_text(json.dumps(rep))
    monkeypatch.setattr("sys.argv", ["x", str(tmp_path / "m.dot"), str(tmp_path / "r.json"), "--out", str(tmp_path / "o.json")])
    check_traces.main()
    out = json.loads((tmp_path / "o.json").read_text())
    assert out["checked"] == 3 and len(out["mismatches"]) == 1 and out["skipped_alphabet"] == 1
    assert out["mismatches"][0]["sequence"] == ["a", "a"]


def test_diff_to_seqs_extracts_distinguishing_sequences(tmp_path, monkeypatch):
    from psm import diff, diff_to_seqs
    a, b = toy_machine(), toy_machine()
    b.states[2].output_fun["b"] = "NO_RESP"
    save_automaton_to_file(a, str(tmp_path / "a"), file_type="dot")
    save_automaton_to_file(b, str(tmp_path / "b"), file_type="dot")
    monkeypatch.setattr("sys.argv", ["x", str(tmp_path / "a.dot"), str(tmp_path / "b.dot"), "--out", str(tmp_path / "d.json")])
    diff.main()
    seqs = diff_to_seqs.sequences(json.loads((tmp_path / "d.json").read_text()))
    assert seqs[0] == ["a", "b", "b"]
    for s in seqs:  # every extracted sequence really distinguishes the two machines
        assert check_traces.predict(a, s) != check_traces.predict(b, s)
