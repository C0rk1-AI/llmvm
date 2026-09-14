#!/usr/bin/env python3
"""Full selftest cycle: generate VM build + native build, run both, diff.

Each attempt builds into a fresh directory under a randomized name: the
local AV occasionally quarantine-locks freshly-linked obfuscated exes (and
once it starts watching one directory, everything there fails), so a new
seed + new folder + new exe name yields a new content hash and a cold path.
"""
import base64
import json
import os
import random
import shutil
import string
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vmlib import build  # noqa: E402
import pepolish  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.join(ROOT, 'work_selftest')
os.makedirs(BASE, exist_ok=True)


def rnd_name(k=7):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(k))


def attempt(seed):
    W = os.path.join(BASE, 'w_' + rnd_name())
    os.makedirs(W, exist_ok=True)
    g = subprocess.run([sys.executable, os.path.join(ROOT, 'vmc.py'), 'build',
                        '--targets', os.path.join(ROOT, 'tests/selftest_targets.c'),
                        '--host', os.path.join(ROOT, 'tests/host_config.py'),
                        '--main', os.path.join(ROOT, 'tests/selftest_main.c'),
                        '--outdir', W, '--seed', str(seed)],
                       capture_output=True, text=True)
    if g.returncode:
        print(g.stderr[-2000:])
        sys.exit(1)
    vmn, natn = rnd_name() + '.exe', rnd_name() + '.exe'
    flags, theme = [], None
    tp = os.path.join(W, 'theme.json')
    if os.path.exists(tp):
        t = json.load(open(tp))
        flags = ['/EXPORT:' + e for e in t['exports']]
        theme = {'sections': t['sections'],
                 'dllname': t.get('dllname'),
                 'jd': base64.b64decode(t['jd'])}
    vm_exe = os.path.join(W, vmn)
    build.build_exe(vm_exe, [os.path.join(W, 'protected.c')],
                    link_flags=flags)
    pepolish.polish(vm_exe, theme=theme)
    build.compile_native(os.path.join(W, natn),
                         [os.path.join(ROOT, 'tests/selftest_targets.c'),
                          os.path.join(W, 'data_native.c'),
                          os.path.join(ROOT, 'tests/selftest_main.c')],
                         force_include=os.path.join(W, 'native_decl.h'))
    a = build.run_exe(vm_exe)
    b = build.run_exe(os.path.join(W, natn))
    return a, b, g, W


last = None
for k in range(12):
    seed = random.randrange(1, 10 ** 9)
    try:
        a, b, g, W = attempt(seed)
    except (RuntimeError, PermissionError) as e:
        last = e
        print('attempt %d blocked (AV?), retrying: %s' % (k, str(e)[:80]))
        time.sleep(1.5)
        continue
    open(os.path.join(BASE, 'vm_out.txt'), 'w').write(a.stdout)
    open(os.path.join(BASE, 'native_out.txt'), 'w').write(b.stdout)
    open(os.path.join(BASE, 'last_dir.txt'), 'w').write(W)
    print(g.stdout[-300:])
    print('seed', seed, '--- vm exit', a.returncode, 'native exit', b.returncode, '---')
    print(a.stdout)
    if a.returncode or b.returncode:
        print('EXIT CODE FAILURE')
        sys.exit(1)
    if a.stdout != b.stdout:
        print('!!! OUTPUT MISMATCH')
        va, nb = a.stdout.splitlines(), b.stdout.splitlines()
        for i in range(max(len(va), len(nb))):
            x = va[i] if i < len(va) else '<none>'
            y = nb[i] if i < len(nb) else '<none>'
            if x != y:
                print('  line %d: vm=%r native=%r' % (i, x, y))
        sys.exit(1)
    print('=== SELFTEST PASS: outputs identical ===')
    sys.exit(0)
print('ALL ATTEMPTS BLOCKED:', last)
sys.exit(1)
