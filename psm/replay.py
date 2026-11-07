"""Replay concrete abstract-input sequences N times against one or more SUTs (via their mappers) and log
every observation plus the SUT container's log for the replay window. This is the evidence for any claim.

  python -m psm.replay --target dropbear2020=8012:psm-dropbear2020 --seq "KEXINIT KEX30 NEWKEYS UA_PK_OK" \
      --reps 5 --out results/replay/smoke.json
  python -m psm.replay --target a=8001:psm-a --target b=8002:psm-b --seq-file seqs.json --reps 5 --out ...
"""
from __future__ import annotations

import argparse
import json
import subprocess
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from psm.mapper_client import MapperClient


def container_logs(name: str, since: str) -> list[str]:
    if not name:
        return []
    try:
        r = subprocess.run(["docker", "logs", "--since", since, name], capture_output=True, text=True, timeout=30)
        return (r.stdout + r.stderr).splitlines()[-200:]
    except Exception as e:  # logs are supporting evidence, never fatal
        return [f"<could not read logs: {e}>"]


def _run_target(client, container, seq, reps):
    since = datetime.now(timezone.utc).isoformat()
    t0 = time.time()
    obs = [client.query(seq) for _ in range(reps)]
    counts = Counter(tuple(o) for o in obs)
    return {
        "observations": obs,
        "distinct": [{"outputs": list(k), "count": v} for k, v in counts.most_common()],
        "deterministic": len(counts) == 1,
        "seconds": round(time.time() - t0, 2),
        "server_log": container_logs(container, since),
    }


def replay(targets: dict, sequences: list[list[str]], reps: int) -> dict:
    """Targets are replayed in parallel threads (each has its own mapper), sequences in order."""
    out = {"started": datetime.now(timezone.utc).isoformat(), "reps": reps, "targets": {}, "sequences": []}
    clients = {}
    for name, (port, container) in targets.items():
        clients[name] = MapperClient("127.0.0.1", port)
        out["targets"][name] = {"mapper_port": port, "container": container}
    with ThreadPoolExecutor(max_workers=max(1, len(targets))) as pool:
        for seq in sequences:
            entry = {"sequence": seq, "results": {}}
            futs = {name: pool.submit(_run_target, clients[name], container, seq, reps)
                    for name, (port, container) in targets.items()}
            for name, f in futs.items():
                entry["results"][name] = f.result()
            finals = {n: tuple(r["distinct"][0]["outputs"]) for n, r in entry["results"].items() if r["deterministic"]}
            entry["all_deterministic"] = all(r["deterministic"] for r in entry["results"].values())
            entry["targets_disagree"] = entry["all_deterministic"] and len(set(finals.values())) > 1
            out["sequences"].append(entry)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", action="append", required=True, help="name=mapper_port[:container]")
    ap.add_argument("--seq", action="append", default=[], help="space-separated input symbols")
    ap.add_argument("--seq-file", help="JSON list of sequences (lists of symbols)")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    targets = {}
    for t in a.target:
        name, rest = t.split("=", 1)
        port, _, container = rest.partition(":")
        targets[name] = (int(port), container)
    seqs = [s.split() for s in a.seq]
    if a.seq_file:
        seqs += json.loads(Path(a.seq_file).read_text())
    res = replay(targets, seqs, a.reps)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=1))
    for e in res["sequences"]:
        print(" ".join(e["sequence"]))
        for n, r in e["results"].items():
            tag = "" if r["deterministic"] else f"  NONDETERMINISTIC {[(' '.join(d['outputs']), d['count']) for d in r['distinct']]}"
            print(f"   {n:14s} {' '.join(r['distinct'][0]['outputs'])}{tag}   ({r['seconds']}s)")


if __name__ == "__main__":
    main()
