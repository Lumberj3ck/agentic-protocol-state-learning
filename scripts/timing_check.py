"""Is the mapper still deterministic with shorter timeouts? Runs fixed and random words N times per target."""
import random, sys, time
from smlearn import testbed
from smlearn.ssh.mapper import SSHMapper, INPUTS

timeout, quiet, reps = float(sys.argv[1]), float(sys.argv[2]), int(sys.argv[3])
rng = random.Random(1)
words = [["KEXINIT", "KEX30", "NEWKEYS", "SR_AUTH", "UA_PW_OK", "CH_OPEN", "CH_REQUEST_EXEC", "CH_CLOSE"]]
words += [[rng.choice(INPUTS) for _ in range(6)] for _ in range(8)]
for name in ["openssh", "dropbear", "asyncssh"]:
    inst = testbed.start(testbed.load_target(name))
    m = SSHMapper(inst.host, inst.port, timeout=timeout, quiet=quiet)
    bad, t0, steps = 0, time.time(), 0
    for w in words:
        outs = set()
        for _ in range(reps):
            m.reset(); outs.add(tuple(m.step(i) for i in w)); steps += len(w)
        if len(outs) > 1:
            bad += 1; print(name, "NONDET", w, outs)
    print(f"{name}: {bad}/{len(words)} nondeterministic words, {(time.time()-t0)/steps*1000:.0f} ms/step")
    m.close(); inst.stop()
