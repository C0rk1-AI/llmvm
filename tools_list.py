#!/usr/bin/env python3
"""List plain-stream instructions per function for a given seed (ground truth)."""
import importlib.util
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vmlib import lang, codegen  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))


def load_host_config(path):
    spec = importlib.util.spec_from_file_location('hostcfg', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m.HOSTS, m.DATA, m.DATA_TYPES


def listing(seed, targets=None, fname=None):
    rng = random.Random(seed)
    src = open(os.path.join(ROOT, 'tests/selftest_targets.c'), encoding='utf-8').read()
    funcs, structs = lang.parse_full(src)
    feats = lang.scan_features(funcs, structs)
    hosts, data, dt = load_host_config(os.path.join(ROOT, 'tests/host_config.py'))
    ctx = codegen.Ctx(rng, funcs, hosts, data, dt,
                      features=feats, structs=structs)
    out = {}
    for fn in funcs:
        gen, cipher, deltas = codegen.build_function(fn, ctx)
        plain, labels_at = codegen.linearize(gen, ctx)
        # decode listing from plain bytes using opcode_map reverse
        rev = {v: k for k, v in ctx.opcode_map.items()}  # semantic -> [bytes]
        alias_to_sem = ctx.opcode_map
        i = 0
        lines = []
        lab_pos = {v: k for k, v in labels_at.items()}
        while i < len(plain):
            opb = plain[i]
            sem = alias_to_sem.get(opb)
            at = i
            if sem is None:
                lines.append('%4d: BYTE %3d (UNMAPPED!)' % (at, opb))
                i += 1
                continue
            if sem == 'PUSHI':
                v = int.from_bytes(plain[i+1:i+9], 'little')
                lines.append('%4d: PUSHI 0x%x' % (at, v))
                i += 9
            elif sem in ('PUSHD', 'LDFL', 'STFL', 'CALLH', 'CALLV'):
                q = plain[i+1] ^ ctx.sch.dmx8(i+1)
                extra = ''
                if sem == 'CALLH':
                    extra = ' (%s/%d)' % ctx.hid_rev.get(q, ('?', 0))
                if sem in ('JMP', 'JT', 'JF'):
                    pass
                lines.append('%4d: %s %d%s' % (at, sem, q, extra))
                i += 2
            elif sem == 'LAA':
                v = int.from_bytes(plain[i+1:i+3], 'little')
                lines.append('%4d: LAA loc+%d' % (at, v))
                i += 3
            elif sem in ('JMP', 'JT', 'JF'):
                rel = int.from_bytes(plain[i+1:i+5], 'little', signed=True)
                tgt = i + 5 + rel
                lines.append('%4d: %s -> %d %s' % (at, sem, tgt,
                            ('[L%d]' % lab_pos[tgt]) if tgt in lab_pos else '[!not a label!]'))
                i += 5
            else:
                lines.append('%4d: %s' % (at, sem))
                i += 1
        out[fn.name] = (lines, plain)
    return out


if __name__ == '__main__':
    seed = int(sys.argv[1])
    want = sys.argv[2] if len(sys.argv) > 2 else 't_ctrl'
    out = listing(seed)
    for name, (lines, plain) in out.items():
        if want and name != want:
            continue
        print('=== %s (%d bytes) ===' % (name, len(plain)))
        print('\n'.join(lines))
