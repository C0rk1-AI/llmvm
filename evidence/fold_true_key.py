"""Ground-truth key fold: regenerate the exact build ctx for the CURRENT
evidence seed (evidence/seed.txt) in-process and fold the runtime key
derivation exactly as kload() does, printing the per-build scheme that an
analyst would need to reproduce for a scripted decryptor.

Historical note: the agent-comparison lines below refer to the retired
881831599 build graded in REPORT.md; they are meaningless for other seeds.
"""
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEMO = os.path.join(ROOT, 'demo')
sys.path.insert(0, ROOT)

from vmlib import lang, codegen, gen_c  # noqa: E402
from vmc import load_host_config  # noqa: E402  (same loader vmc uses)


def u32(x):
    return x & 0xFFFFFFFF


def rotl(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


SEED = int(open(os.path.join(HERE, 'seed.txt')).read().strip())
print('replaying evidence seed', SEED)
rng = random.Random(SEED)
src = open(os.path.join(DEMO, 'vm_targets.c'), encoding='utf-8').read()
funcs = lang.parse(src)
hosts, data, data_types = load_host_config(os.path.join(DEMO, 'host_config.py'))
ctx = codegen.Ctx(rng, funcs, hosts, data, data_types)

funcs_ir = []
for fn in funcs:
    gen, cipher, deltas = codegen.build_function(fn, ctx)
    funcs_ir.append((fn, cipher))
decoys, tables = gen_c.gen_decoys(rng)

print('build-time ctx: K1=%08x K2=%08x K3=%08x MK=%x' % (ctx.K1, ctx.K2, ctx.K3, ctx.MK))
s = ctx.sch
print('per-build scheme: kset=%d kmix=(%d,%x,%d,%x,%d) rot=%d cmb=%d sh=%d '
      'l=(%s,%s,%s) pc1=%08x dmx=(%08x,%08x,%d,%d)'
      % (s.kset, s.kms1, s.kmm1, s.kms2, s.kmm2, s.kms3, s.rot, s.cmb, s.sh,
         s.l1, s.l2, s.l3, s.pc1, s.ds, s.dp, s.da, s.dsh))

dmap = {d.name: d for d in decoys}
k1v = u32(dmap['dec_bmp_probe'].value ^ dmap['dec_rle_scan'].value)
k2v = u32(dmap['dec_jpeg_idct'].value + dmap['dec_huff_walk'].value)
k3v = u32(dmap['dec_md5_mix'].value ^ dmap['dec_quant_check'].value
          ^ dmap['dec_png_crc'].value)
ADJ1 = u32(rotl(k1v, 3) ^ ctx.K1)
ADJ2 = u32(u32(k2v * 0x6acd) ^ ctx.K2)
ADJ3 = u32(ctx.K3 - k3v)
mkb = u32(rotl(ctx.K1, 9) + ctx.K2)
ADJM = ctx.MK ^ mkb
print('ADJ1=%08x ADJ2=%08x ADJ3=%08x ADJM=%x (mkb=%08x)'
      % (ADJ1, ADJ2, ADJ3, ADJM, mkb))

# runtime kload(), no-debugger path
a = k1v
b = k2v
c = k3v
G_k1 = rotl(a, 3) ^ ADJ1
G_k2 = u32(b * 0x6acd) ^ ADJ2
G_k3 = u32(c + ADJ3)
G_mk = u64 = (rotl(G_k1, 9) + G_k2) & 0xFFFFFFFF ^ ADJM

print()
print('TRUE  no-debugger: G_k1=%08x G_k2=%08x G_k3=%08x G_mk(mask)=%x'
      % (G_k1, G_k2, G_k3, G_mk))
if SEED == 881831599:
    print('agents folded    : A40=0x440A4D93 A44=0xFE620D6D A48=0xF0B19040 A50=0x2E336C8B')
print()
# debugger path: a ^= 0x35d31f, b += 7
ad = k1v ^ 0x35d31f
bd = u32(k2v + 7)
G_k1d = rotl(ad, 3) ^ ADJ1
G_k2d = u32(bd * 0x6acd) ^ ADJ2
G_mk_d = ((rotl(G_k1d, 9) + G_k2d) & 0xFFFFFFFF) ^ ADJM
print('TRUE  debugger   : G_k1=%08x G_k2=%08x mask=%x' % (G_k1d, G_k2d, G_mk_d))
if SEED == 881831599:
    print('agents (dbg fold): A40=0x45A4D56B A44=0xFE6719C0 A50=0x74DFAF35')

# also verify determinism of regeneration: re-emit and compare to the shipped
# artifact (main include emitted as a repo-relative path, so the byte-exact
# comparison holds in any checkout — the shipped protected.c line 2452 was
# normalized the same way)
main_rel = os.path.relpath(os.path.join(DEMO, 'demo_main.c'), ROOT).replace('\\', '/')
out = gen_c.emit(ctx, funcs_ir, decoys, tables, main_rel, trace=False)
ref = open(os.path.join(HERE, 'protected.c'), encoding='utf-8').read()
print()
print('regenerated protected.c identical to evidence/protected.c:', out == ref)
