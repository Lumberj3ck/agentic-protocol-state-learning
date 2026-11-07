"""Learn a Mealy model of one SUT through its mapper with AALpy L*.

  python -m psm.learn --name dropbear2020 --port 8012 --alphabet KEXINIT,KEX30,NEWKEYS,SR_AUTH,UA_PK_OK

Writes results/models/<name>.dot and results/learning/<name>/{stats.json,nondet.jsonl,cache.json,hyp-*.dot}.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from aalpy.learning_algs import run_Lstar
from aalpy.oracles import RandomWordEqOracle, StatePrefixEqOracle
from aalpy.utils import save_automaton_to_file

from psm.mapper_client import MapperClient
from psm.robust_sul import RobustSUL


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--alphabet", required=True)
    ap.add_argument("--walks", type=int, default=150, help="random-word equivalence tests per round")
    ap.add_argument("--min-len", type=int, default=3)
    ap.add_argument("--max-len", type=int, default=9)
    ap.add_argument("--repeat-prob", type=float, default=0.1)
    ap.add_argument("--max-rounds", type=int, default=None)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--oracle", choices=["random", "stateprefix"], default="stateprefix")
    ap.add_argument("--walks-per-state", type=int, default=25)
    ap.add_argument("--cache-in", help="cache.json of an earlier run against the SAME SUT+mapper config")
    a = ap.parse_args()

    alphabet = a.alphabet.split(",")
    run_dir = Path("results/learning") / a.name
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "nondet.jsonl").unlink(missing_ok=True)
    sul = RobustSUL(MapperClient("127.0.0.1", a.port), log_dir=run_dir, repeat_prob=a.repeat_prob, seed=a.seed)
    import random
    random.seed(a.seed)
    if a.cache_in:
        for k, v in json.loads(Path(a.cache_in).read_text()):
            sul.cache[tuple(k)] = tuple(v)
        print(f"seeded cache with {len(sul.cache)} entries from {a.cache_in}")
    if a.oracle == "random":
        eq = RandomWordEqOracle(alphabet, sul, num_walks=a.walks, min_walk_len=a.min_len, max_walk_len=a.max_len,
                                reset_after_cex=True)
    else:
        eq = StatePrefixEqOracle(alphabet, sul, walks_per_state=a.walks_per_state, walk_len=a.max_len)
    t0 = time.time()
    model, data = run_Lstar(alphabet, sul, eq, automaton_type="mealy", cache_and_non_det_check=False,
                            max_learning_rounds=a.max_rounds, return_data=True, print_level=2)
    elapsed = time.time() - t0
    Path("results/models").mkdir(parents=True, exist_ok=True)
    save_automaton_to_file(model, f"results/models/{a.name}", file_type="dot")
    sul.save_cache(run_dir / "cache.json")
    stats = {
        "name": a.name, "alphabet": alphabet, "states": model.size,
        "learning_rounds": data.get("learning_rounds"),
        "aalpy_queries_learning": data.get("queries_learning"), "aalpy_steps_learning": data.get("steps_learning"),
        "aalpy_queries_eq_oracle": data.get("queries_eq_oracle"), "aalpy_steps_eq_oracle": data.get("steps_eq_oracle"),
        "sut": dict(sul.stats), "seconds": round(elapsed, 1),
        "eq_oracle": {"type": a.oracle, "walks_per_round": a.walks, "walks_per_state": a.walks_per_state,
                      "len": [a.min_len, a.max_len]}, "cache_in": a.cache_in,
        "repeat_prob": a.repeat_prob, "seed": a.seed,
        "finished": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    (run_dir / "stats.json").write_text(json.dumps(stats, indent=1))
    print(json.dumps(stats, indent=1))


if __name__ == "__main__":
    main()
