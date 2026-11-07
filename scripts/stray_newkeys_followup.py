"""Bounded diagnostics against existing loopback Docker targets only."""
import subprocess
import time
from smlearn import testbed
from smlearn.ssh.mapper import SSHMapper


def docker(inst, *args):
    return subprocess.check_output(['docker', *args[:1], inst.container_id, *args[1:]], text=True).strip()


def connect(inst, strict=True, auth=False):
    m = SSHMapper(inst.host, inst.port, timeout=.5, quiet=.1, strict_kex=strict)
    m.reset()
    word = ['KEXINIT', 'KEX30', 'NEWKEYS', 'SR_AUTH'] + (['UA_PW_OK'] if auth else [])
    print('prefix', [(s, m.step(s)) for s in word], flush=True)
    return m


if __name__ == '__main__':
    inst = testbed.start(testbed.load_target('libssh'))
    peers = []
    try:
        print('target', inst.host, 'libssh 0.12.2', flush=True)
        for variant, strict, reset in [('A', True, False), ('B', False, False), ('C', True, True)]:
            m = connect(inst, strict)
            peers.append(m)
            m.timeout = 5
            print(variant, 'NEWKEYS', m.step('NEWKEYS'), flush=True)
            if reset:
                m.outgoing.sequence = 0
            print(variant, 'UA_PW_OK', m.step('UA_PW_OK'), flush=True)
        m = connect(inst, auth=True)
        peers.append(m)
        m.timeout = 5
        print('post-auth NEWKEYS', m.step('NEWKEYS'), flush=True)
        print('post-auth CH_OPEN', m.step('CH_OPEN'), flush=True)
        healthy = connect(inst, auth=True)
        print('parallel healthy CH_OPEN', healthy.step('CH_OPEN'), flush=True)
        healthy.close()
        print('process-before', docker(inst, 'exec', 'sh', '-c', 'cat /proc/1/stat; cat /proc/1/status | sed -n "/Threads:/p"'), flush=True)
        start = time.monotonic()
        for i in range(12):
            print('idle', (i + 1) * 10, peers[0]._collect(10), flush=True)
        print('idle elapsed', round(time.monotonic() - start, 2), flush=True)
        print('process-after', docker(inst, 'exec', 'sh', '-c', 'cat /proc/1/stat; cat /proc/1/status | sed -n "/Threads:/p"'), flush=True)
        print('stats', docker(inst, 'stats', '--no-stream', '--format', '{{.CPUPerc}} {{.MemUsage}} {{.PIDs}}'), flush=True)
        print('logs-before-close', repr(inst.logs()), flush=True)
        for m in peers:
            m.close()
        time.sleep(1)
        print('logs-after-close', repr(inst.logs()), flush=True)
    finally:
        for m in peers:
            m.close()
        inst.stop()
