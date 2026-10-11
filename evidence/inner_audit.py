#!/usr/bin/env python3
"""Audit the REAL build's inner programs (exact vmc rng order) vs reference.

Replicates vmc.py build in-process for a given seed, captures the InnerBuild
(via a subclass hook inside a real gen_c.emit() run, so every rng draw matches
the shipped protected.c), then executes every inner program through
inner_exec (python mirror of the C interpreter) against native semantics.
"""
import importlib.util
import os
import random
import sys
from types import SimpleNamespace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from vmlib import enc, inner, codegen, gen_c, lang  # noqa: E402

SEED = int(sys.argv[1]) if len(sys.argv) > 1 else 533752418


def load_host_config(path):
    spec = importlib.util.spec_from_file_location('hostcfg', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m.HOSTS, m.DATA, m.DATA_TYPES


def build_ib(seed):
    rng = random.Random(seed)
    src = open(os.path.join(ROOT, 'tests/selftest_targets.c'),
               encoding='utf-8').read()
    funcs, structs = lang.parse_full(src)
    feats = lang.scan_features(funcs, structs)
    hosts, data, data_types = load_host_config(
        os.path.join(ROOT, 'tests/host_config.py'))
    ctx = codegen.Ctx(rng, funcs, hosts, data, data_types,
                      features=feats, structs=structs)
    funcs_ir = []
    for fn in funcs:
        gen, cipher, deltas = codegen.build_function(fn, ctx)
        funcs_ir.append((fn, cipher))
    decoys, tables = gen_c.gen_decoys(rng)
    captured = {}
    orig = gen_c.InnerBuild

    class CapIB(orig):
        def __init__(self, c):
            super().__init__(c)
            captured['ib'] = self

    gen_c.InnerBuild = CapIB
    try:
        gen_c.emit(ctx, funcs_ir, decoys, tables,
                   os.path.join(ROOT, 'tests/selftest_main.c'))
    finally:
        gen_c.InnerBuild = orig
    return ctx, captured['ib']


ctx, ib = build_ib(SEED)
sch = ctx.sch
opmap = inner.imopmap(ib.imap)
print('outer kset=%d inner kset=%d I1..3=%08x/%08x/%08x IMK=%08x'
      % (sch.kset, ib.isch.kset, ib.I1, ib.I2, ib.I3, ib.IMK))


def ksbyte(bc, q, k1, k2, k3):
    return bc[q] ^ sch.ks8(q, k1, k2, k3)


def run_case(sem, plain, bc, k1, k2, k3, st_in, fr, db, cond=None, d=None):
    """Build outer state + reference expectation, run inner program, diff."""
    out = inner.Outer(bc=bc, k1=k1, k2=k2, k3=k3, dmx_fn=sch.dmx8,
                      ks8_fn=sch.ks8, nfr=64)
    out.fr = list(fr)
    out.db = db
    out.st = list(st_in)
    if sem == 'PUSHI':
        v = int.from_bytes(bytes(ksbyte(bc, q, k1, k2, k3)
                                 for q in range(8)), 'little')
        ref = dict(pc=8, lp=7, pp=8, st=list(st_in) + [v], k=(k1, k2, k3))
    elif sem == 'PUSHD':
        q = ksbyte(bc, 0, k1, k2, k3) ^ sch.dmx8(0)
        ref = dict(pc=1, lp=0, pp=1, st=list(st_in) + [db[q]],
                   k=(k1, k2, k3))
    elif sem == 'LDFL':
        q = ksbyte(bc, 0, k1, k2, k3) ^ sch.dmx8(0)
        ref = dict(pc=1, lp=0, pp=1, st=list(st_in) + [fr[q & 63]],
                   k=(k1, k2, k3))
    elif sem == 'STFL':
        q = ksbyte(bc, 0, k1, k2, k3) ^ sch.dmx8(0)
        fr2 = list(fr)
        fr2[q & 63] = st_in[0]
        ref = dict(pc=1, lp=0, pp=1, st=[], fr=fr2, k=(k1, k2, k3))
    elif sem == 'JMP':
        rel = int.from_bytes(bytes(ksbyte(bc, q, k1, k2, k3)
                                   for q in range(0, 4)), 'little',
                             signed=True)
        ref = dict(pc=(4 + rel) & 0xFFFFFFFF, lp=3, pp=4,
                   st=list(st_in), k=(k1, k2, k3))
    elif sem in ('JT', 'JF'):
        rel = int.from_bytes(bytes(ksbyte(bc, q, k1, k2, k3)
                                   for q in range(0, 4)), 'little',
                             signed=True)
        take = (cond != 0) if sem == 'JT' else (cond == 0)
        tgt = (4 + rel) & 0xFFFFFFFF if take else 4
        ref = dict(pc=tgt, lp=3, pp=4, st=[], k=(k1, k2, k3))
    elif sem == 'KSET':
        ref = dict(pc=0, lp=0, pp=0, st=[],
                   k=sch.kset_apply(k1, k2, k3, d))
    else:
        raise KeyError(sem)

    if sem in ('JT', 'JF'):
        out.st = [cond]
    if sem == 'KSET':
        out.st = [d]
    steps = inner.inner_exec(plain, opmap, out)
    got_k = (out.k1, out.k2, out.k3)
    errs = []
    if got_k != tuple(x & 0xFFFFFFFF for x in ref['k']):
        errs.append('k=%06x/%06x/%06x want %06x/%06x/%06x'
                    % (got_k + tuple(x & 0xFFFFFFFF for x in ref['k'])))
    if out.pc != ref['pc']:
        errs.append('pc=%d want %d' % (out.pc, ref['pc']))
    def _m(x):
        return x if isinstance(x, bytes) else x & 0xFFFFFFFFFFFFFFFF

    if [_m(x) for x in out.st] != [_m(x) for x in ref['st']]:
        errs.append('st=%s want %s'
                    % ([hex(x) if not isinstance(x, bytes) else x[:4]
                        for x in out.st],
                       [hex(x) if not isinstance(x, bytes) else x[:4]
                        for x in ref['st']]))
    if 'fr' in ref and out.fr != ref['fr']:
        errs.append('fr differs')
    return errs, steps


trng = random.Random(0xC0FFEE)
bad = total = 0
for sem in gen_c.INNERIZED:
    for byte in ctx.aliases[sem]:
        cip = ib.programs[byte]
        plain = bytes(b ^ ib.isch.ks8(i, ib.I1, ib.I2, ib.I3)
                      for i, b in enumerate(cip))
        for trial in range(8):
            bc = bytes(trng.randrange(256) for _ in range(96))
            k1, k2, k3 = (trng.getrandbits(32) for _ in range(3))
            fr = [trng.getrandbits(64) for _ in range(64)]
            db = [bytes(trng.randrange(256) for _ in range(3))
                  for _ in range(256)]
            st_in = [trng.getrandbits(64)]
            cond = trng.choice([0, 1, 2, 0xdeadbeef])
            d = trng.getrandbits(64)
            try:
                errs, steps = run_case(sem, plain, bc, k1, k2, k3,
                                       st_in, fr, db, cond=cond, d=d)
            except Exception as e:
                errs, steps = ['EXC %r' % e], -1
            total += 1
            if errs:
                bad += 1
                print('MISMATCH sem=%s byte=%#04x trial=%d steps=%d: %s'
                      % (sem, byte, trial, steps, '; '.join(errs)))
                if bad >= 10:
                    print('... stopping at 10')
                    sys.exit(1)
print('audited %d executions, %d bad' % (total, bad))
if bad:
    sys.exit(1)
