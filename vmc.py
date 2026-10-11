#!/usr/bin/env python3
"""vmc — LLM-targeted code virtualizer for Windows PE.

Usage:
  python vmc.py build --targets T.c --host host_config.py --main main.c \
                      --outdir work --name demo [--seed 1337]

Produces:
  work/protected.c     generated VM interpreter + wrappers + decoys
  work/data_native.c   plain data arrays (for native control builds)
  work/native_decl.h   extern decls for compiling targets natively
  work/theme.json      per-build decoy narrative (sections/exports/.jd blob)
"""
import argparse
import base64
import importlib.util
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vmlib import lang, codegen, gen_c, decoy_lib  # noqa: E402


def load_host_config(path):
    spec = importlib.util.spec_from_file_location('hostcfg', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m.HOSTS, m.DATA, m.DATA_TYPES


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    b = sub.add_parser('build')
    b.add_argument('--targets', required=True)
    b.add_argument('--host', required=True)
    b.add_argument('--main', required=True)
    b.add_argument('--outdir', required=True)
    b.add_argument('--name', default='demo')
    b.add_argument('--seed', type=int, default=1337)
    b.add_argument('--trace', action='store_true')
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    rng = random.Random(args.seed)

    src = open(args.targets, encoding='utf-8').read()
    funcs, structs = lang.parse_full(src)
    feats = lang.scan_features(funcs, structs)
    hosts, data, data_types = load_host_config(args.host)
    # typed double hosts (e.g. sqrt) need math.h on both sides; the targets
    # source itself has no #include directives (implicit int decls suffice
    # for the int-returning legacy hosts, not for double-returning ones)
    has_dhost = any(h.get('ret') == 'd' or 'd' in (h.get('sig') or '')
                    for h in hosts.values())

    ctx = codegen.Ctx(rng, funcs, hosts, data, data_types,
                      features=feats, structs=structs)

    funcs_ir = []
    for fn in funcs:
        gen, cipher, deltas = codegen.build_function(fn, ctx)
        funcs_ir.append((fn, cipher))
        print(f'  vm fn {fn.name}: {len(cipher)} cipher bytes, '
              f'{gen.nslots} frame slots, {len(deltas)} kset layers')

    decoys, tables = gen_c.gen_decoys(rng)
    main_path = os.path.abspath(args.main).replace('\\', '/')
    protected = gen_c.emit(ctx, funcs_ir, decoys, tables, main_path,
                           trace=args.trace)

    open(os.path.join(args.outdir, 'protected.c'), 'w',
         encoding='utf-8').write(protected)

    # per-build decoy narrative: feeds link-time export aliases (run_demo /
    # run_selftest read theme.json) and the pepolish metadata pass
    combo = decoy_lib.select(rng)
    theme = {
        'theme': combo.theme_id,
        'kind': combo.kind,
        'blended': combo.blended,
        'sections': combo.sections,
        'exports': ['%s=%s' % (alias, dec) for alias, dec in combo.exports],
        'dllname': combo.dllname,
        'jd': base64.b64encode(combo.jd_blob).decode('ascii'),
    }
    open(os.path.join(args.outdir, 'theme.json'), 'w',
         encoding='utf-8').write(json.dumps(theme, indent=1))

    # native-side data + decls
    lines = ['/* plain data for native control build */',
             '#include <stdint.h>', '']
    decl = ['#pragma once', '#include <stdint.h>', '']
    if has_dhost:
        decl += ['', '#include <math.h>']
    if 'varargs' in feats:
        # native equivalents of the VM variadic builtins (subset-C source
        # uses vv_start()/vv_next() inside `...` functions; on the VM side
        # they compile to a marker / the VNEXT op)
        decl += ['', '#include <stdarg.h>',
                 '#define vv_start() va_list vv_ap; va_start(vv_ap, nv)',
                 '#define vv_next()  va_arg(vv_ap, uint64_t)']
    for name, blob in data.items():
        base, ptr = data_types[name]
        ct = gen_c.TY_C[base] + '*' * ptr
        arr = ', '.join('0x%02x' % v for v in blob)
        lines.append('const %s%s[%d] = {%s};' % (ct, name, len(blob), arr))
        decl.append('extern const %s%s[%d];' % (ct, name, len(blob)))
    open(os.path.join(args.outdir, 'data_native.c'), 'w').write('\n'.join(lines))
    open(os.path.join(args.outdir, 'native_decl.h'), 'w').write('\n'.join(decl))
    open(os.path.join(args.outdir, 'legend.txt'), 'w').write(
        '\n'.join('%d %s' % (op, sem) for op, sem in sorted(ctx.opcode_map.items())))

    print(f'  decoys: {len(decoys)}, opcodes mapped: {len(ctx.opcode_map)}, '
          f'data slots: {len(ctx.data_slots)}')
    print(f'  theme: {combo.theme_id} ({combo.kind}) blended={combo.blended}, '
          f'exports={len(combo.exports)}, .jd={len(combo.jd_blob)}B')
    print('  wrote protected.c / data_native.c / native_decl.h / theme.json')


if __name__ == '__main__':
    main()
