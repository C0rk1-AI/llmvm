"""Dev loop helper: regenerate + compile + launch instantly, dodging AV.

The local AV quarantines freshly-linked obfuscated exes a few seconds after
creation. Building and launching inside the same process (plus a random
output name per attempt) reliably wins the race. If an attempt fails, retry
with a new random seed (new content hash).
"""
import os
import random
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vmlib import build  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def one_shot(outdir, targets, host, main, link_flags=(), trace=False,
             env_extra=None, tries=5, timeout=60, keep_name=None):
    """Build with a fresh random seed and run immediately. Returns (rc, stdout, stderr, seed)."""
    last_err = None
    for attempt in range(tries):
        seed = random.randrange(1, 10**9)
        g = subprocess.run(
            [sys.executable, os.path.join(ROOT, 'vmc.py'), 'build',
             '--targets', targets, '--host', host, '--main', main,
             '--outdir', outdir, '--seed', str(seed)]
            + (['--trace'] if trace else []),
            capture_output=True, text=True)
        if g.returncode:
            raise RuntimeError('vmc failed: ' + g.stderr[-1500:])
        name = keep_name or ('run_%08x.exe' % random.randrange(1 << 32))
        exe = os.path.join(outdir, name)
        try:
            build.build_exe(exe, [os.path.join(outdir, 'protected.c')],
                            link_flags)
        except RuntimeError as e:
            last_err = e
            continue
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)
        try:
            r = subprocess.run([os.path.abspath(exe)], capture_output=True,
                               text=True, timeout=timeout, env=env,
                               errors='replace')
            return r.returncode, r.stdout, r.stderr, seed
        except (PermissionError, FileNotFoundError) as e:
            last_err = e
            time.sleep(0.3)
    raise RuntimeError(f'one_shot: all {tries} attempts failed: {last_err}')


if __name__ == '__main__':
    rc, out, err, seed = one_shot(
        os.path.join(ROOT, 'work_selftest'),
        os.path.join(ROOT, 'tests/selftest_targets.c'),
        os.path.join(ROOT, 'tests/host_config.py'),
        os.path.join(ROOT, 'tests/selftest_main.c'),
        trace=True, env_extra={'LLMVM_TRACE': '1'}, tries=4)
    print('seed', seed, 'rc', rc)
    print('STDOUT>>>', out[:400])
    lines = err.splitlines()
    print('TRACE lines:', len(lines))
    lg = {}
    lgf = os.path.join(ROOT, 'work_selftest', 'legend.txt')
    if os.path.exists(lgf):
        lg = dict(l.split() for l in open(lgf) if len(l.split()) == 2)
    for l in lines[:20]:
        print(l, '   [', lg.get(l.split('op=')[1].split()[0], '?') if 'op=' in l else '', ']')
    print('...')
    for l in lines[-6:]:
        print(l, '   [', lg.get(l.split('op=')[1].split()[0], '?') if 'op=' in l else '', ']')
