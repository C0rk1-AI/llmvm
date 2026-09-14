"""Ground-truth INNER keys for the current evidence build (v3-a):
captures the real InnerBuild (exact rng order via emit-time subclass hook)
and prints I1..3 / IMK + inner scheme — what an analyst must reproduce to
lift any inner program."""
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from vmlib import lang, codegen, gen_c  # noqa: E402
from vmc import load_host_config  # noqa: E402

SEED = int(open(os.path.join(HERE, 'seed.txt')).read().strip())
rng = random.Random(SEED)
src = open(os.path.join(ROOT, 'demo', 'vm_targets.c'),
           encoding='utf-8').read()
funcs = lang.parse(src)
hosts, data, dt = load_host_config(os.path.join(ROOT, 'demo', 'host_config.py'))
ctx = codegen.Ctx(rng, funcs, hosts, data, dt)
funcs_ir = []
for fn in funcs:
    _, cipher, _ = codegen.build_function(fn, ctx)
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
    main_rel = os.path.relpath(os.path.join(ROOT, 'demo', 'demo_main.c'),
                               ROOT).replace('\\', '/')
    gen_c.emit(ctx, funcs_ir, decoys, tables, main_rel)
finally:
    gen_c.InnerBuild = orig
ib = captured['ib']
print('seed %d inner: I1=%08x I2=%08x I3=%08x IMK=%08x' %
      (SEED, ib.I1, ib.I2, ib.I3, ib.IMK))
s = ib.isch
print('inner scheme: kset=%d kmix=(%d,%x,%d,%x,%d) rot=%d cmb=%d sh=%d '
      'l=(%s,%s,%s) pc1=%08x' % (s.kset, s.kms1, s.kmm1, s.kms2, s.kmm2,
                                 s.kms3, s.rot, s.cmb, s.sh, s.l1, s.l2,
                                 s.l3, s.pc1))
print('innerized aliases:', {sem: ctx.aliases[sem]
                             for sem in gen_c.INNERIZED})
