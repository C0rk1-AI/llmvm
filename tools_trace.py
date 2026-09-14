#!/usr/bin/env python3
"""Run one traced selftest attempt, save trace, annotate against legend."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vmlib import devloop  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
W = os.path.join(ROOT, 'work_selftest')

rc, out, err, seed = devloop.one_shot(
    W, os.path.join(ROOT, 'tests/selftest_targets.c'),
    os.path.join(ROOT, 'tests/host_config.py'),
    os.path.join(ROOT, 'tests/selftest_main.c'),
    trace=True, env_extra={'LLMVM_TRACE': '1'}, tries=4)
print('seed', seed, 'rc', rc)
print('STDOUT>>>', repr(out[:300]))

open(os.path.join(W, 'trace.txt'), 'w', encoding='utf-8').write(err)
lg = {}
for l in open(os.path.join(W, 'legend.txt'), encoding='utf-8'):
    p = l.split()
    if len(p) == 2:
        lg[p[0]] = p[1]

lines = []
for l in err.splitlines():
    m = re.match(r'pc=\s*(\d+) op=\s*(\d+) sp=\s*(-?\d+)', l)
    if m:
        lines.append('%-14s op=%-4s sp=%-4s %s'
                     % (m.group(1), m.group(2), m.group(3),
                        lg.get(m.group(2), '???')))
    else:
        lines.append('    >> ' + l)
open(os.path.join(W, 'trace_ann.txt'), 'w', encoding='utf-8').write('\n'.join(lines))
print('wrote trace.txt / trace_ann.txt,', len(lines), 'lines')
