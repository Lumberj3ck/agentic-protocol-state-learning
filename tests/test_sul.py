"""Tests for the mapper socket client and the caching, nondeterminism-aware SUL, against a fake mapper."""
import random
import socket
import threading

import pytest
from aalpy.automata import MealyMachine, MealyState
from aalpy.learning_algs import run_Lstar
from aalpy.oracles import RandomWordEqOracle

from psm.mapper_client import MapperClient
from psm.robust_sul import RobustSUL


def toy_machine():
    """3-state toy 'protocol': a then b succeeds; anything else out of order kills the connection."""
    s0, s1, s2, sink = (MealyState(n) for n in ("s0", "s1", "s2", "sink"))
    s0.transitions.update(a=s1, b=sink)
    s0.output_fun.update(a="KEXINIT", b="DISCONNECT")
    s1.transitions.update(a=s1, b=s2)
    s1.output_fun.update(a="NO_RESP", b="KEX31+NEWKEYS")
    s2.transitions.update(a=sink, b=s2)
    s2.output_fun.update(a="DISCONNECT", b="UNIMPL")
    sink.transitions.update(a=sink, b=sink)
    sink.output_fun.update(a="NO_CONN", b="NO_CONN")
    return MealyMachine(s0, [s0, s1, s2, sink])


class FakeMapper:
    """Speaks the ssh-fuzzer mapper line protocol over TCP, backed by a Mealy machine.
    flaky: probability that a 'KEX31+NEWKEYS' output is split into 'KEX31' (a timing artifact)."""

    def __init__(self, machine, flaky=0.0, seed=0):
        self.m, self.flaky, self.rng = machine, flaky, random.Random(seed)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.commands_run = 0
        threading.Thread(target=self._serve, daemon=True).start()

    def _out(self, sym):
        o = self.m.step(sym)
        self.commands_run += 1
        if o == "KEX31+NEWKEYS" and self.rng.random() < self.flaky:
            return "KEX31"
        return o

    def _serve(self):
        conn, _ = self.sock.accept()
        f = conn.makefile("rb")
        while True:
            line = f.readline()
            if not line:
                return
            outs = []
            for c in line.decode().split():
                if c == "reset":
                    self.m.reset_to_initial()
                    outs.append("resetok")
                else:
                    outs.append(self._out(c))
            conn.sendall((" ".join(outs) + "\n").encode())


def test_client_query_and_step():
    fm = FakeMapper(toy_machine())
    c = MapperClient("127.0.0.1", fm.port)
    assert c.query(["a", "b", "b"]) == ["KEXINIT", "KEX31+NEWKEYS", "UNIMPL"]
    c.reset()
    assert c.step("b") == "DISCONNECT"
    assert c.step("a") == "NO_CONN"


def test_cache_and_sink_shortcut(tmp_path):
    fm = FakeMapper(toy_machine())
    sul = RobustSUL(MapperClient("127.0.0.1", fm.port), log_dir=tmp_path, repeat_prob=0.0)
    assert sul.query(("b", "a")) == ["DISCONNECT", "NO_CONN"]
    before = fm.commands_run
    # Extension of a NO_CONN-terminated word is answered without touching the SUT.
    assert sul.query(("b", "a", "a", "b")) == ["DISCONNECT", "NO_CONN", "NO_CONN", "NO_CONN"]
    # A cached word (and its prefixes) too.
    assert sul.query(("b",)) == ["DISCONNECT"]
    assert fm.commands_run == before
    assert sul.stats["sink_shortcuts"] >= 1 and sul.stats["cache_hits"] >= 1


def test_step_mode_matches_query_mode(tmp_path):
    fm = FakeMapper(toy_machine())
    sul = RobustSUL(MapperClient("127.0.0.1", fm.port), log_dir=tmp_path, repeat_prob=0.0)
    sul.pre()
    outs = [sul.step(x) for x in ("a", "a", "b", "b")]
    sul.post()
    assert outs == ["KEXINIT", "NO_RESP", "KEX31+NEWKEYS", "UNIMPL"]
    assert sul.query(("a", "a", "b", "b")) == outs  # now cached


def test_nondeterminism_is_logged_and_majority_wins(tmp_path):
    fm = FakeMapper(toy_machine(), flaky=0.2, seed=3)
    sul = RobustSUL(MapperClient("127.0.0.1", fm.port), log_dir=tmp_path, repeat_prob=1.0, repeats=6)
    for _ in range(15):
        sul.query(("a", "b", "b"))
        sul.cache.clear()  # force re-execution to provoke disagreement
    assert sul.stats["nondet_events"] >= 1
    log = (tmp_path / "nondet.jsonl").read_text().strip().splitlines()
    assert log, "nondeterminism must be logged"
    # Majority answer is the true behaviour.
    assert sul.query(("a", "b", "b")) == ["KEXINIT", "KEX31+NEWKEYS", "UNIMPL"]


def test_learns_toy_machine_end_to_end(tmp_path):
    fm = FakeMapper(toy_machine())
    sul = RobustSUL(MapperClient("127.0.0.1", fm.port), log_dir=tmp_path, repeat_prob=0.0)
    eq = RandomWordEqOracle(["a", "b"], sul, num_walks=200, min_walk_len=2, max_walk_len=6)
    model = run_Lstar(["a", "b"], sul, eq, automaton_type="mealy", cache_and_non_det_check=False, print_level=0)
    assert model.size == 4


def test_mapper_crash_is_logged_and_query_retried(tmp_path):
    fm = FakeMapper(toy_machine())
    client = MapperClient("127.0.0.1", fm.port)
    sul = RobustSUL(client, log_dir=tmp_path, repeat_prob=0.0)
    calls = {"n": 0}
    real_query = client.query

    def flaky_query(word):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("mapper closed the connection")
        return real_query(word)

    client.query = flaky_query
    client.reconnect = lambda wait=60.0: None  # the fake mapper never actually went away
    assert sul.query(("a", "b")) == ["KEXINIT", "KEX31+NEWKEYS"]
    assert sul.stats["harness_errors"] == 1
    assert "mapper closed" in (tmp_path / "harness_errors.jsonl").read_text()
