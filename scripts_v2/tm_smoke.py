"""Smoke test: can the teammate's mapper talk to our SUTs?  Happy path + wrong password, strict on/off, 3 reps.
  .venv-tm/bin/python scripts_v2/tm_smoke.py --out results/v2/A/tm_smoke.json"""
import json
import sys
import traceback

import tm_common as tc

WORDS = [["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "UA_PW_OK", "CH_OPEN", "CH_REQUEST_EXEC", "CH_CLOSE"],
         ["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "UA_PW_NOK"],
         ["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "UA_PW_OK", "KEXINIT", "KEX30", "NEWKEYS", "CH_OPEN"]]


def main():
    out = sys.argv[sys.argv.index("--out") + 1]
    res = []
    for sut in ("openssh", "dropbear", "gossh"):
        for strict in (False, True):
            for w in WORDS:
                runs, err = [], None
                try:
                    m = tc.tm_mapper(sut, strict)
                    for _ in range(3):
                        runs.append(tc.tm_query(m, w))
                    active = m.strict_kex_active
                    ver = m.server_version.decode()
                    trace = m.trace
                    m.close()
                except Exception:
                    err, active, ver, trace = traceback.format_exc(), None, None, []
                r = {"sut": sut, "strict_kex": strict, "word": w, "runs": runs, "deterministic": len({tuple(x) for x in runs}) == 1,
                     "strict_kex_active": active, "server_version": ver, "error": err,
                     "last_trace": [(d, n) for d, n, _ in trace]}
                res.append(r)
                print(sut, strict, active, ver, " ".join(runs[0]) if runs else err, "" if r["deterministic"] else "NONDET", flush=True)
    json.dump(res, open(out, "w"), indent=1)


if __name__ == "__main__":
    main()
