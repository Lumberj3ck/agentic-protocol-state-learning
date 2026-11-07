"""Learn a model of one of OUR SUTs with the TEAMMATE'S learner and mapper (their RobustSUL, ParallelEqOracle with
their SSH seed paths, AALpy KV), pointed at our running container instead of their testbed.
  .venv-tm/bin/python scripts_v2/tm_learn.py gossh --strict 0 --alphabet KEXINIT,KEX30,... --out results/v2/A/tm_models/gossh_ns"""
import argparse
import json
import time
from pathlib import Path

import tm_common as tc
from aalpy.learning_algs import run_KV
from aalpy.utils import save_automaton_to_file
from smlearn.learn import SSH_SEED_PATHS, ParallelEqOracle, QueryLog, RobustSUL

COMMON = "KEXINIT,KEX30,NEWKEYS,SR_AUTH,SR_CONN,UA_PW_OK,CH_OPEN"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("sut")
    p.add_argument("--strict", type=int, default=0)
    p.add_argument("--alphabet", default=COMMON)
    p.add_argument("--instances", type=int, default=3)
    p.add_argument("--walks-per-state", type=int, default=20)
    p.add_argument("--max-suffix", type=int, default=6)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--seeds", type=Path, help="JSON list of extra seed words (their mechanism for refuted witnesses)")
    a = p.parse_args()
    alphabet = a.alphabet.split(",")
    a.out.mkdir(parents=True, exist_ok=True)
    log = QueryLog(a.out / "queries.jsonl")
    mappers = [tc.tm_mapper(a.sut, bool(a.strict)) for _ in range(a.instances)]
    sul = RobustSUL(mappers[0], log)
    eq = ParallelEqOracle(alphabet, sul, mappers[1:] or mappers, log, walks_per_state=a.walks_per_state,
                          max_suffix=a.max_suffix, seed_paths=SSH_SEED_PATHS + (json.loads(a.seeds.read_text()) if a.seeds else []))
    t0 = time.time()
    model, info = run_KV(alphabet, sul, eq, automaton_type="mealy", cache_and_non_det_check=False,
                         return_data=True, print_level=1)
    save_automaton_to_file(model, str(a.out / "model"), file_type="dot")
    stats = {"sut": a.sut, "port": tc.SUTS[a.sut][0], "strict_kex": bool(a.strict), "alphabet": alphabet,
             "mapper_kw": tc.TM_TIMING, "instances": a.instances, "states": len(model.states),
             "rounds": info.get("learning_rounds"), "mq": sul.num_queries, "mq_steps": sul.num_steps,
             "eq": eq.num_queries, "eq_steps": eq.num_steps, "nondet_events": sul.nondet_events,
             "reset_failures": sul.reset_failures + eq.reset_failures, "seconds": round(time.time() - t0, 1),
             "strict_kex_active": mappers[0].strict_kex_active, "extra_seeds": str(a.seeds) if a.seeds else None,
             "learner": "teammate smlearn.learn (RobustSUL, ParallelEqOracle, SSH_SEED_PATHS) @ 76b49e1, AALpy run_KV"}
    (a.out / "learn.json").write_text(json.dumps(stats, indent=2) + "\n")
    for m in mappers:
        m.close()
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
