"""Replay input words on a real target and print outputs and the packet trace.

    uv run python scripts/replay.py <target> "KEXINIT KEX30 NEWKEYS ..." ["..."] [--reps N] [--trace]
"""
import sys
from smlearn import testbed
from smlearn.ssh.mapper import SSHMapper

args = [a for a in sys.argv[1:] if not a.startswith("--")]
reps = int(next((a.split("=")[1] for a in sys.argv if a.startswith("--reps=")), 3))
show_trace = "--trace" in sys.argv
target = testbed.load_target(args[0])
testbed.build(target)
inst = testbed.start(target)
try:
    m = SSHMapper(inst.host, inst.port, user=target.user, password=target.password, timeout=0.8, quiet=0.2)
    for word in args[1:]:
        word = word.split()
        runs = []
        for _ in range(reps):
            m.reset()
            runs.append([m.step(i) for i in word])
        print(f"\n{target.name}: {' '.join(word)}")
        print(f"  deterministic over {reps}: {all(r == runs[0] for r in runs)}")
        for i, o in zip(word, runs[0]):
            print(f"  {i:16} -> {o}")
        if show_trace:
            for d, n, h in m.trace:
                print(f"    {d} {n:18} {h[:80]}")
    m.close()
finally:
    inst.stop()
