#!/usr/bin/env python3
"""Differential fuzz: inner-VM programs vs reference native semantics.

For many random builds (fresh enc.Scheme draw, fresh inner programs), run
each INNERIZED outer-handler program through inner.inner_exec and compare
the resulting outer state against an INDEPENDENT reference implementation
of the original native handlers (built directly on enc.Scheme.ks8/dmx8/
kset_apply — the ground truth the C must match bit for bit).
"""
import os
import random
import sys
from types import SimpleNamespace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from vmlib import enc, inner, gen_c  # noqa: E402

M32 = enc.M32
M64 = enc.M64

NFR = 64


def sext32(v):
    v &= M32
    return v | 0xFFFFFFFF00000000 if v & 0x80000000 else v


class Ref:
    """Reference outer state + native-handler semantics (v2 shapes)."""

    def __init__(self, rng, sch):
        self.sch = sch
        self.bc = bytes(rng.randrange(256) for _ in range(128))
        self.pc = rng.randrange(32)
        self.pp = rng.randrange(1000)
        self.lp = rng.randrange(1000)
        self.st = [rng.getrandbits(64) for _ in range(3)]
        self.fr = [rng.getrandbits(64) for _ in range(NFR)]
        self.db = [rng.getrandbits(64) for _ in range(256)]
        self.k1 = rng.getrandbits(32)
        self.k2 = rng.getrandbits(32)
        self.k3 = rng.getrandbits(32)

    def nxb(self):
        p = self.pc
        b = self.bc[p] ^ self.sch.ks8(p, self.k1, self.k2, self.k3)
        self.pc = (self.pc + 1) & M32
        self.pp = (self.pp + 1) & M32
        self.lp = p
        return b

    def nx64(self):
        r = 0
        for i in range(8):
            r |= self.nxb() << (8 * i)
        return r & M64

    def nx32s(self):
        r = 0
        for i in range(4):
            r |= self.nxb() << (8 * i)
        return r & M32

    def run(self, sem):
        if sem == 'PUSHI':
            self.st.append(self.nx64())
        elif sem == 'PUSHD':
            o = self.nxb()
            q = o ^ self.sch.dmx8(self.lp)
            self.st.append(self.db[q])
        elif sem == 'LDFL':
            o = self.nxb()
            q = o ^ self.sch.dmx8(self.lp)
            self.st.append(self.fr[q & 63])
        elif sem == 'STFL':
            o = self.nxb()
            q = o ^ self.sch.dmx8(self.lp)
            self.fr[q & 63] = self.st.pop()
        elif sem == 'JMP':
            r = self.nx32s()
            tgt = sext32(r)
            self.pc = (self.pc + tgt) & M32
        elif sem == 'JT':
            c = self.st.pop()
            r = self.nx32s()
            tgt = sext32(r)
            if c:
                self.pc = (self.pc + tgt) & M32
        elif sem == 'JF':
            c = self.st.pop()
            r = self.nx32s()
            tgt = sext32(r)
            if not c:
                self.pc = (self.pc + tgt) & M32
        elif sem == 'KSET':
            d = self.st.pop()
            self.k1, self.k2, self.k3 = self.sch.kset_apply(
                self.k1, self.k2, self.k3, d)
        else:
            raise KeyError(sem)


def snap(o):
    return (o.pc, o.pp, o.lp, list(o.st), list(o.fr),
            o.k1, o.k2, o.k3)


def one_build(seed):
    rng = random.Random(seed)
    sch = enc.Scheme(rng)
    # fake ctx with just what InnerBuild needs
    pool = list(range(256))
    rng.shuffle(pool)
    aliases = {}
    for sem in gen_c.INNERIZED:
        n = 1 + rng.randrange(3)
        aliases[sem] = pool[:n]
        del pool[:n]
    ctx = SimpleNamespace(rng=rng, sch=sch, aliases=aliases)
    ib = gen_c.InnerBuild(ctx)
    opmap = inner.imopmap(ib.imap)
    checked = 0
    for byte, cip in ib.programs.items():
        sem = aliases and next(s for s in gen_c.INNERIZED
                               if byte in aliases[s])
        plain = bytes(b ^ ib.isch.ks8(i, ib.I1, ib.I2, ib.I3)
                      for i, b in enumerate(cip))
        for t in range(4):
            trng = random.Random(seed * 10003 + byte * 7 + t)
            ref = Ref(trng, sch)
            out = inner.Outer(bc=ref.bc, k1=ref.k1, k2=ref.k2, k3=ref.k3,
                              dmx_fn=sch.dmx8, ks8_fn=sch.ks8,
                              db=ref.db, nfr=NFR)
            out.pc, out.pp, out.lp = ref.pc, ref.pp, ref.lp
            out.st = list(ref.st)
            out.fr = list(ref.fr)
            ref.run(sem)
            try:
                steps = inner_exec_safe(plain, opmap, out)
            except (IndexError, AssertionError, KeyError) as e:
                print('EXEC ERROR seed=%d byte=0x%02x sem=%s case=%d: %r'
                      % (seed, byte, sem, t, e))
                return False
            if snap(ref) != snap(out):
                print('MISMATCH seed=%d byte=0x%02x sem=%s case=%d'
                      % (seed, byte, sem, t))
                a, b = snap(ref), snap(out)
                for nm, x, y in zip(('pc', 'pp', 'lp', 'st', 'fr',
                                     'k1', 'k2', 'k3'), a, b):
                    if x != y:
                        print('   %s: ref=%r got=%r' % (nm, x, y))
                return False
            if steps >= 100000:
                print('STEP LIMIT seed=%d byte=0x%02x' % (seed, byte))
                return False
            checked += 1
    return checked


def inner_exec_safe(plain, opmap, outer):
    return inner.inner_exec(plain, opmap, outer)


def main():
    total = 0
    for seed in range(300):
        r = one_build(seed)
        if r is False:
            print('FAILED at seed', seed)
            sys.exit(1)
        total += r
    print('inner_check: OK — %d program executions across 300 builds '
          '(8 semantics x aliases x 4 states)' % total)


if __name__ == '__main__':
    main()
