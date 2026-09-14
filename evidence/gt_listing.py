"""Ground-truth listing of the CURRENT evidence build (seed from
evidence/seed.txt): per-function plain bytecode listing with KSET layer
positions and deltas — used to grade blind-agent decryption attempts.

IMPORTANT: mirrors build_function() instruction-for-instruction (generate ->
gen_prologue -> prepend -> linearize ONCE -> encrypt). Do NOT call
build_function() and then linearize() again — linearize draws ctx.rng
(ctx.pick per instruction), so a second call shifts the stream and yields a
different (wrong) build for every function after the first.
"""
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from vmlib import lang, codegen  # noqa: E402
from vmc import load_host_config  # noqa: E402

SEED = int(open(os.path.join(HERE, 'seed.txt')).read().strip())
rng = random.Random(SEED)
src = open(os.path.join(ROOT, 'demo', 'vm_targets.c'), encoding='utf-8').read()
funcs = lang.parse(src)
hosts, data, dt = load_host_config(os.path.join(ROOT, 'demo', 'host_config.py'))
ctx = codegen.Ctx(rng, funcs, hosts, data, dt)


def build_keep_plain(fn, ctx):
    gen = codegen.FnGen(fn, ctx).generate()
    pro, deltas = codegen.gen_prologue(ctx)
    gen.code = pro + gen.code
    plain, labels_at = codegen.linearize(gen, ctx)
    cipher = codegen.encrypt(plain, gen, deltas, ctx)
    return gen, plain, cipher, deltas, labels_at


print('seed %d  funcs=%d' % (SEED, len(funcs)))
for fn in funcs:
    gen, plain, cipher, deltas, labels_at = build_keep_plain(fn, ctx)
    i, ksn, lines = 0, 0, []
    lab_pos = {v: k for k, v in labels_at.items()}
    while i < len(plain):
        sem = ctx.opcode_map.get(plain[i])
        if sem is None:
            lines.append('%4d: UNMAPPED %02x' % (i, plain[i]))
            i += 1
            continue
        if sem == 'PUSHI':
            v = int.from_bytes(plain[i + 1:i + 9], 'little')
            lines.append('%4d: PUSHI 0x%x' % (i, v))
            i += 9
        elif sem in ('PUSHD', 'LDFL', 'STFL', 'CALLH', 'CALLV'):
            q = plain[i + 1] ^ ctx.sch.dmx8(i + 1)
            extra = ' (%s/%d)' % ctx.hid_rev.get(q, ('?', 0)) if sem == 'CALLH' else ''
            lines.append('%4d: %s %d%s' % (i, sem, q, extra))
            i += 2
        elif sem in ('JMP', 'JT', 'JF'):
            rel = int.from_bytes(plain[i + 1:i + 5], 'little', signed=True)
            tgt = i + 5 + rel
            lines.append('%4d: %s -> %d %s' % (i, sem, tgt,
                        ('[L%d]' % lab_pos[tgt]) if tgt in lab_pos else '[!not a label!]'))
            i += 5
        else:
            tag = ''
            if sem == 'KSET':
                tag = '  <== KSET layer %d delta=0x%016x' % (ksn, deltas[ksn])
                ksn += 1
            lines.append('%4d: %s%s' % (i, sem, tag))
            i += 1
    print()
    print('=== %s (%d bytes, %d KSET layers, %d mapped opcodes) ==='
          % (fn.name, len(plain), len(deltas), len(ctx.opcode_map)))
    print('\n'.join(lines))
    # save plain bytes for blob comparison
    open(os.path.join(HERE, 'gt_%s.bin' % fn.name), 'wb').write(plain)
