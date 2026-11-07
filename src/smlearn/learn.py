"""Learn a Mealy machine of one target implementation.

    uv run python -m smlearn.learn openssh --instances 4

Membership queries go to one container.
Equivalence testing, which is most of the queries, is spread over a pool of containers.
Every query and its answer is logged to results/<target>/queries.jsonl,
so every model state and every disagreement can be replayed.
"""

import argparse
import json
import random
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from aalpy.base import SUL, Oracle
from aalpy.learning_algs import run_KV
from aalpy.utils import save_automaton_to_file

from smlearn import testbed

RESULTS = Path(__file__).resolve().parents[2] / "results"


def make_mapper(inst: testbed.Instance, **kw):
    from smlearn.ssh.mapper import SSHMapper
    t = inst.target
    return SSHMapper(inst.host, inst.port, user=t.user, password=t.password, **kw)


class QueryLog:
    def __init__(self, path: Path):
        self.f = path.open("w")
        self.lock = threading.Lock()

    def write(self, kind: str, word, out, **extra):
        with self.lock:
            self.f.write(json.dumps({"kind": kind, "in": list(word), "out": list(out), **extra}) + "\n")
            self.f.flush()


class RobustSUL(SUL):
    """Runs each query on a mapper; answers are cached in a prefix tree.

    If a new answer contradicts an earlier one on a shared prefix, the query is
    repeated `votes` times and the majority answer is kept.
    Every such event is logged, so mapper nondeterminism is measured, not hidden.
    """

    def __init__(self, mapper, log: QueryLog, votes: int = 5):
        super().__init__()
        self.mapper, self.log, self.votes = mapper, log, votes
        self.cache: dict[tuple, str] = {}
        self.nondet_events = 0

    def _run(self, word):
        self.mapper.reset()
        return [self.mapper.step(i) for i in word]

    def query(self, word):
        word = tuple(word)
        if word and word in self.cache:
            return [self.cache[word[:k]] for k in range(1, len(word) + 1)]
        self.num_queries += 1
        self.num_steps += len(word)
        out = self._run(word)
        if any(self.cache.get(word[:k], o) != o for k, o in enumerate(out, 1)):
            self.nondet_events += 1
            runs = [tuple(out)] + [tuple(self._run(word)) for _ in range(self.votes - 1)]
            out, n = Counter(runs).most_common(1)[0]
            out = list(out)
            self.log.write("nondet", word, out, votes=n, of=len(runs), runs=[list(r) for r in runs])
        for k, o in enumerate(out, 1):
            self.cache[word[:k]] = o
        self.log.write("mq", word, out)
        return out

    # AALpy's step-wise interface is not used: query() is overridden.
    def pre(self): pass
    def post(self): pass
    def step(self, letter): raise NotImplementedError


# Protocol knowledge for the equivalence oracle: paths that reach deep states.
# Uniform random walks almost never complete a 5-step handshake out of 17 inputs,
# so without these the learner stops at the pre-authentication states.
SSH_SEED_PATHS = [
    ["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "UA_PW_OK", "CH_OPEN", "CH_REQUEST_EXEC", "CH_EOF", "CH_CLOSE"],
    ["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "UA_PW_OK", "KEXINIT", "KEX30", "NEWKEYS", "CH_OPEN", "CH_CLOSE"],
    ["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "UA_PW_NOK", "UA_PW_NOK", "UA_NONE", "UA_PW_OK", "CH_OPEN"],
    ["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "UA_PW_OK", "CH_OPEN", "CH_OPEN", "CH_CLOSE", "CH_CLOSE"],
]


class ParallelEqOracle(Oracle):
    """Conformance testing spread over a pool of mappers.

    Test words are (1) every seed-path prefix followed by every single input,
    (2) seed-path prefixes followed by random suffixes, and
    (3) every hypothesis state's access sequence followed by random suffixes.
    Answers are cached across rounds (the mapper is deterministic; the main SUL
    re-checks any counterexample with its majority vote before it is returned).
    """

    def __init__(self, alphabet, sul: RobustSUL, pool, log: QueryLog,
                 walks_per_state=20, max_suffix=6, seed=0, seed_paths=(), walks_per_prefix=8):
        super().__init__(alphabet, sul)
        self.pool, self.log = pool, log
        self.walks_per_state, self.max_suffix = walks_per_state, max_suffix
        self.seed_paths = [[a for a in p if a in alphabet] for p in seed_paths]
        self.walks_per_prefix = walks_per_prefix
        self.rng = random.Random(seed)
        self.free = list(range(len(pool)))
        self.lock = threading.Lock()
        self.cache: dict[tuple, list] = {}

    def _suffix(self):
        return tuple(self.rng.choice(self.alphabet) for _ in range(self.rng.randint(1, self.max_suffix)))

    def _words(self, hypothesis):
        words = set()
        for path in self.seed_paths:
            for k in range(len(path) + 1):
                prefix = tuple(path[:k])
                words.update(prefix + (a,) for a in self.alphabet)
                words.update(prefix + self._suffix() for _ in range(self.walks_per_prefix))
        for state in hypothesis.states:
            words.update(tuple(state.prefix) + self._suffix() for _ in range(self.walks_per_state))
        return sorted(words, key=lambda w: (len(w), w))

    def _run_on_pool(self, word):
        with self.lock:
            idx = self.free.pop()
        try:
            m = self.pool[idx]
            m.reset()
            return [m.step(i) for i in word]
        finally:
            with self.lock:
                self.free.append(idx)

    def _check(self, hypothesis, word, out):
        hyp = hypothesis.execute_sequence(hypothesis.initial_state, word)
        # Confirm on the main SUL (with its majority vote) before trusting a counterexample.
        return list(hyp) != list(out) and list(self.sul.query(word)) != list(hyp)

    def find_cex(self, hypothesis):
        hypothesis.compute_prefixes()
        words = self._words(hypothesis)
        for word in words:                       # cached answers first: free to check
            if word in self.cache and self._check(hypothesis, word, self.cache[word]):
                return word
        todo = [w for w in words if w not in self.cache]
        with ThreadPoolExecutor(len(self.pool)) as ex:
            for word, out in zip(todo, ex.map(self._run_on_pool, todo)):
                self.cache[word] = out
                self.num_queries += 1
                self.num_steps += len(word)
                self.log.write("eq", word, out)
                if self._check(hypothesis, word, out):
                    ex.shutdown(wait=False, cancel_futures=True)
                    return word
        return None


def learn(name: str, instances: int = 4, alphabet=None, out_dir: Path | None = None,
          walks_per_state: int = 20, max_suffix: int = 6, **mapper_kw):
    from smlearn.ssh.mapper import INPUTS
    alphabet = list(alphabet or INPUTS)
    target = testbed.load_target(name)
    testbed.build(target)
    out_dir = out_dir or RESULTS / name
    out_dir.mkdir(parents=True, exist_ok=True)
    log = QueryLog(out_dir / "queries.jsonl")

    insts = [testbed.start(target) for _ in range(instances)]
    mappers = [make_mapper(i, **mapper_kw) for i in insts]
    try:
        sul = RobustSUL(mappers[0], log)
        eq = ParallelEqOracle(alphabet, sul, mappers[1:] or mappers, log,
                              walks_per_state=walks_per_state, max_suffix=max_suffix,
                              seed_paths=SSH_SEED_PATHS)
        t0 = time.time()
        model, info = run_KV(alphabet, sul, eq, automaton_type="mealy",
                             cache_and_non_det_check=False, return_data=True, print_level=1)
        elapsed = time.time() - t0
        save_automaton_to_file(model, str(out_dir / "model"), file_type="dot")
        stats = {
            "target": name, "implementation": target.implementation, "source": target.source,
            "alphabet": alphabet, "mapper_kw": mapper_kw, "instances": instances,
            "states": len(model.states), "rounds": info.get("learning_rounds"),
            "mq": sul.num_queries, "mq_steps": sul.num_steps,
            "eq": eq.num_queries, "eq_steps": eq.num_steps,
            "nondet_events": sul.nondet_events, "seconds": round(elapsed, 1),
            "eq_oracle": {"seed_paths": SSH_SEED_PATHS, "walks_per_state": walks_per_state,
                          "max_suffix": max_suffix},
            "strict_kex_active": getattr(mappers[0], "strict_kex_active", None),
        }
        (out_dir / "learn.json").write_text(json.dumps(stats, indent=2) + "\n")
        return model, stats
    finally:
        for m in mappers:
            m.close()
        for i in insts:
            i.stop()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("--instances", type=int, default=4)
    p.add_argument("--alphabet", help="comma-separated subset of the input alphabet")
    p.add_argument("--out", type=Path)
    p.add_argument("--walks-per-state", type=int, default=20)
    p.add_argument("--max-suffix", type=int, default=6)
    p.add_argument("--timeout", type=float)
    p.add_argument("--quiet", type=float)
    p.add_argument("--no-strict-kex", action="store_true")
    a = p.parse_args()
    kw = {k: v for k, v in {"timeout": a.timeout, "quiet": a.quiet}.items() if v is not None}
    if a.no_strict_kex:
        kw["strict_kex"] = False
    _, stats = learn(a.target, a.instances, a.alphabet.split(",") if a.alphabet else None,
                     a.out, a.walks_per_state, a.max_suffix, **kw)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
