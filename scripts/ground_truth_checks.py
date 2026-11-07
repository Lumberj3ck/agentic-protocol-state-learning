"""Replay the literature-derived ground-truth words (literature/ssh-ground-truth.md) on the real targets.

    uv run python scripts/ground_truth_checks.py

Each word runs 3 times per target, with strict KEX offered and not offered,
and the outputs are written to results/ground-truth/checks.json.
"""

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from smlearn import testbed
from smlearn.ssh.mapper import SSHMapper

HS = ["KEXINIT", "KEX30", "NEWKEYS"]
AUTH = HS + ["SR_AUTH", "UA_PW_OK"]

CHECKS = {
    "GT1-late-window-IGNORE": ["KEXINIT", "KEX30", "IGNORE", "NEWKEYS", "SR_AUTH"],
    "GT1-late-window-DEBUG": ["KEXINIT", "KEX30", "DEBUG", "NEWKEYS", "SR_AUTH"],
    "GT1-late-window-UNIMPL": ["KEXINIT", "KEX30", "UNIMPLEMENTED", "NEWKEYS", "SR_AUTH"],
    "GT1-repeated-KEX30": ["KEXINIT", "KEX30", "KEX30", "NEWKEYS", "SR_AUTH"],
    "GT2-IGNORE-in-kex": ["KEXINIT", "IGNORE", "KEX30", "NEWKEYS", "SR_AUTH"],
    "GT2-IGNORE-first": ["IGNORE", "KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH"],
    "GT3-auth-without-SR": HS + ["UA_PW_OK", "CH_OPEN"],
    "GT4-SR-after-auth": AUTH + ["SR_AUTH"],
    "GT4-UA-after-auth": AUTH + ["UA_NONE"],
    "GT4-CH_OPEN-before-auth": HS + ["SR_AUTH", "CH_OPEN"],
    "GT5-rekey-before-auth": HS + ["SR_AUTH", "KEXINIT", "KEX30", "NEWKEYS", "UA_PW_OK"],
    "GT5-channel-during-rekey": AUTH + ["KEXINIT", "KEX30", "CH_OPEN", "CH_CLOSE", "NEWKEYS"],
}


def run_target(name):
    inst = testbed.start(testbed.load_target(name))
    rows = {}
    try:
        for strict in (True, False):
            m = SSHMapper(inst.host, inst.port, timeout=0.4, quiet=0.1, strict_kex=strict)
            for cid, word in CHECKS.items():
                runs = []
                for _ in range(3):
                    m.reset()
                    runs.append([m.step(i) for i in word])
                rows[f"{cid}|strict={strict}"] = {
                    "word": word, "out": runs[0], "deterministic": all(r == runs[0] for r in runs),
                    "strict_kex_active": m.strict_kex_active,
                }
            m.close()
    finally:
        inst.stop()
    return name, rows


def main():
    out = Path(__file__).resolve().parents[1] / "results" / "ground-truth"
    out.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(3) as ex:
        results = dict(ex.map(run_target, ["openssh", "dropbear", "asyncssh"]))
    (out / "checks.json").write_text(json.dumps(results, indent=2) + "\n")
    for key in results["openssh"]:
        print(f"\n{key}: {' '.join(results['openssh'][key]['word'])}")
        for t, rows in results.items():
            r = rows[key]
            print(f"  {t:9} {'' if r['deterministic'] else 'NONDET '}{' | '.join(r['out'])}")


if __name__ == "__main__":
    main()
