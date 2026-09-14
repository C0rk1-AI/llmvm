#!/usr/bin/env python3
"""Disassemble the REAL build's inner program for one outer alias byte."""
import sys

sys.argv = [sys.argv[0]] + sys.argv[1:]
import os
src_dir = os.path.dirname(os.path.abspath(__file__))
audit = open(os.path.join(src_dir, 'inner_audit.py')).read().split('trng = random.Random')[0]
g = {'__file__': os.path.join(src_dir, 'inner_audit.py'), '__name__': 'audit'}
_args = sys.argv[1:]
sys.argv = [sys.argv[0]] + _args[:1]  # first arg (if numeric) = seed
if not _args or not _args[0].isdigit():
    sys.argv = [sys.argv[0]]  # audit prefix defaults the seed
exec(audit, g)
sys.argv = [sys.argv[0]] + _args

ib, ctx, inner, opmap = g['ib'], g['ctx'], g['inner'], g['opmap']
want_sem = sys.argv[2] if len(sys.argv) > 2 else 'PUSHI'
for sem in g['gen_c'].INNERIZED:
    if sem != want_sem:
        continue
    for byte in ctx.aliases[sem]:
        cip = ib.programs[byte]
        plain = bytes(b ^ ib.isch.ks8(i, ib.I1, ib.I2, ib.I3)
                      for i, b in enumerate(cip))
        print('== %s alias %#04x len=%d' % (sem, byte, len(plain)))
        pc = 0
        while pc < len(plain):
            op = plain[pc]
            s = opmap[op]
            sz = inner.INNER_SIZES[s]
            extra = ''
            if s == 'IPUSH':
                extra = '0x%x' % int.from_bytes(plain[pc + 1:pc + 9], 'little')
            elif s == 'IROL32':
                extra = str(plain[pc + 1] & 31)
            elif s in ('IJMP', 'IJT', 'IJF'):
                rel = int.from_bytes(plain[pc + 1:pc + 3], 'little',
                                     signed=True)
                extra = '-> %d' % (pc + 3 + rel)
            print('  %3d: %-9s %-20s (op %02x)' % (pc, s, extra, op))
            pc += sz
