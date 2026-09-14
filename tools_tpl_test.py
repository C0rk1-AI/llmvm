#!/usr/bin/env python3
"""Exhaustive template verifier: every polymorphic handler expression is
compiled as a C function and compared against the native operator over
random + boundary values. Catches template bugs deterministically."""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vmlib import build
from vmlib.gen_c import gen_binop_expr  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
W = os.path.join(ROOT, 'work_selftest')


class SeqRng:
    """rng whose choice(list) walks the list in order."""

    def __init__(self):
        self.i = 0

    def choice(self, seq):
        v = seq[self.i % len(seq)]
        self.i += 1
        return v

    def randrange(self, a, b=None):
        return 0


BINOPS = ['ADD', 'SUB', 'AND', 'OR', 'XOR', 'LTU', 'LEQU', 'GTU', 'GEQU',
          'EQU', 'NEQ', 'SHL', 'SHR', 'SAR', 'DIVU', 'MODU', 'DIVS', 'MODS']

REF = {
    'ADD': 'v1 + v2', 'SUB': 'v1 - v2', 'MUL': 'v1 * v2',
    'AND': 'v1 & v2', 'OR': 'v1 | v2', 'XOR': 'v1 ^ v2',
    'LTU': '(uint64_t)(v1 < v2)', 'LEQU': '(uint64_t)(v1 <= v2)',
    'GTU': '(uint64_t)(v1 > v2)', 'GEQU': '(uint64_t)(v1 >= v2)',
    'LTS': '(uint64_t)((int64_t)v1 < (int64_t)v2)',
    'LEQS': '(uint64_t)((int64_t)v1 <= (int64_t)v2)',
    'GTS': '(uint64_t)((int64_t)v1 > (int64_t)v2)',
    'GEQS': '(uint64_t)((int64_t)v1 >= (int64_t)v2)',
    'EQU': '(uint64_t)(v1 == v2)', 'NEQ': '(uint64_t)(v1 != v2)',
    'SHL': 'v1 << (v2 & 63u)', 'SHR': 'v1 >> (v2 & 63u)',
    'SAR': '(uint64_t)((int64_t)v1 >> (v2 & 63u))',
    'DIVU': 'v2 ? v1 / v2 : 0', 'MODU': 'v2 ? v1 % v2 : 0',
    'DIVS': 'v2 ? (uint64_t)((int64_t)v1 / (int64_t)v2) : 0',
    'MODS': 'v2 ? (uint64_t)((int64_t)v1 % (int64_t)v2) : 0',
}


def collect(op, n=6):
    """All distinct template expressions for op."""
    seen = []
    for k in range(n):
        r = SeqRng()
        r.i = k
        e = gen_binop_expr(r, op)
        if e not in seen:
            seen.append(e)
    return seen


def main():
    fns = []
    calls = []
    for op in BINOPS:
        for i, e in enumerate(collect(op)):
            name = 'tpl_%s_%d' % (op, i)
            fns.append('static uint64_t %s(uint64_t v1, uint64_t v2){ '
                       'return (uint64_t)(%s); }' % (name, e))
            calls.append((name, op, e))
    rng = random.Random(1234)
    vals = [0, 1, 2, 3, 7, 8, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFFFFFFFF,
            0x100000000, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000,
            0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 63, 64, 65]
    pairs = [(a, b) for a in vals for b in vals]
    for _ in range(400):
        pairs.append((rng.getrandbits(64), rng.getrandbits(64)))
        pairs.append((rng.getrandbits(32), rng.getrandbits(64)))
    src = ['#include <stdint.h>', '#include <stdio.h>']
    src += fns
    src.append('static uint64_t REF(uint64_t v1, uint64_t v2, int op);')
    src.append('''
int main(void){
    static const uint64_t A[%d] = {%s};
    static const uint64_t B[%d] = {%s};
    int bad = 0; unsigned i;
''' % (len(pairs), ','.join('0x%016xull' % a for a, _ in pairs),
       len(pairs), ','.join('0x%016xull' % b for _, b in pairs)))
    for name, op, e in calls:
        ref = REF[op].replace('v1', 'A[i]').replace('v2', 'B[i]')
        if op in ('DIVS', 'MODS'):
            guard = ('if (B[i] != 0 && !(B[i] == 0xFFFFFFFFFFFFFFFFull && '
                     'A[i] == 0x8000000000000000ull)) ')
        elif op in ('DIVU', 'MODU'):
            guard = 'if (B[i] != 0) '
        else:
            guard = ''
        src.append('    for (i = 0; i < %d; i++) { %s{ uint64_t r = %s(A[i], B[i]);'
                   ' uint64_t x = (uint64_t)(%s);'
                   ' if (r != x) { if (bad < 10) printf("BAD %%s A=%%016llx B=%%016llx got %%016llx want %%016llx\\n", "%s", (unsigned long long)A[i], (unsigned long long)B[i], (unsigned long long)r, (unsigned long long)x); bad++; } } }'
                   % (len(pairs), guard, name, ref, name))
    src.append('    printf("templates checked: %%d, mismatches: %%d\\n", %d, bad);\n'
               '    return bad ? 1 : 0;\n}' % len(calls))
    open(os.path.join(W, 'tpl_test.c'), 'w').write('\n'.join(src))
    exe = os.path.join(W, 'tpl_test.exe')
    build.run('cl /nologo /O2 /W3 /MT "%s\\tpl_test.c" /Fe:"%s" /link'
              % (W, exe))
    r = build.run_exe(exe)
    print(r.stdout)
    sys.exit(0 if r.returncode == 0 and 'mismatches: 0' in r.stdout else 1)


if __name__ == '__main__':
    main()
