#!/usr/bin/env python3
"""Build the demo pair: plain control exe + VM-protected exe, run both, diff.

Keeps a record of the seed used so the protected exe can be regenerated
deterministically for idalib analysis even if the local AV quarantines it.
"""
import argparse
import base64
import json
import os
import random
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vmlib import build  # noqa: E402
import pepolish  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
DEMO = os.path.join(ROOT, 'demo')
W = os.path.join(ROOT, 'work_demo')

# fallback export aliases when no theme.json exists (dec_* decoys are
# non-static in protected.c)
FAKE_EXPORTS = [
    '/EXPORT:jpeg_idct_8x8=dec_jpeg_idct',
    '/EXPORT:jpeg_huff_decode=dec_huff_walk',
    '/EXPORT:png_crc32_table=dec_png_crc',
    '/EXPORT:jpeg_dct_quant=dec_quant_check',
]


def load_theme(outdir):
    """theme.json written by vmc.py build -> link flags + pepolish theme."""
    p = os.path.join(outdir, 'theme.json')
    if not os.path.exists(p):
        return FAKE_EXPORTS, None
    t = json.load(open(p))
    flags = ['/EXPORT:' + e for e in t['exports']]
    theme = {'sections': t['sections'],
             'dllname': t.get('dllname'),
             'jd': base64.b64decode(t['jd'])}
    return flags, theme


def gen(seed):
    g = subprocess.run([sys.executable, os.path.join(ROOT, 'vmc.py'), 'build',
                        '--targets', os.path.join(DEMO, 'vm_targets.c'),
                        '--host', os.path.join(DEMO, 'host_config.py'),
                        '--main', os.path.join(DEMO, 'demo_main.c'),
                        '--outdir', W, '--seed', str(seed)],
                       capture_output=True, text=True)
    if g.returncode:
        print(g.stderr[-2000:])
        sys.exit(1)
    return g.stdout


def one(seed, extra_srcs=(), link_flags=(), keep=True):
    os.makedirs(W, exist_ok=True)
    out = gen(seed)
    srcs = [os.path.join(W, 'protected.c')] + list(extra_srcs)
    vm_exe = os.path.join(W, 'demo_vm.exe')
    plain_exe = os.path.join(W, 'demo_plain.exe')
    build.compile_native(plain_exe,
                         [os.path.join(DEMO, 'vm_targets.c'),
                          os.path.join(W, 'data_native.c'),
                          os.path.join(DEMO, 'demo_main.c')])
    build.build_exe(vm_exe, srcs, link_flags)
    a = build.run_exe(vm_exe)
    b = build.run_exe(plain_exe)
    open(os.path.join(W, 'vm_out.txt'), 'w').write(a.stdout)
    open(os.path.join(W, 'plain_out.txt'), 'w').write(b.stdout)
    open(os.path.join(W, 'seed.txt'), 'w').write(str(seed))
    print(out.splitlines()[-3] if out else '')
    print('seed', seed, 'vm rc', a.returncode, 'plain rc', b.returncode)
    print('--- vm ---');    print(a.stdout, end='')
    print('--- plain ---'); print(b.stdout, end='')
    if a.returncode or b.returncode:
        print('EXIT FAILURE'); return None
    if a.stdout != b.stdout:
        print('!!! OUTPUT MISMATCH'); return None
    print('=== DEMO PASS: outputs identical ===')
    return seed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--seed', type=int, default=None)
    ap.add_argument('--tries', type=int, default=10)
    ap.add_argument('--nopepolish', action='store_true',
                    help='skip the PE metadata decoy pass')
    args = ap.parse_args()
    os.makedirs(W, exist_ok=True)
    plain_exe = os.path.join(W, 'demo_plain.exe')
    if not os.path.exists(plain_exe):
        srcs = [os.path.join(DEMO, 'vm_targets.c'),
                os.path.join(DEMO, 'demo_main.c')]
        dn = os.path.join(W, 'data_native.c')
        if os.path.exists(dn) and os.path.getsize(dn) > 60:
            srcs.insert(1, dn)
        build.compile_native(plain_exe, srcs,
                             force_include=os.path.join(W, 'native_decl.h'))
    b = build.run_exe(plain_exe)
    open(os.path.join(W, 'plain_out.txt'), 'w').write(b.stdout)
    for k in range(args.tries):
        seed = args.seed if (args.seed and k == 0) else random.randrange(1, 10 ** 9)
        try:
            gen(seed)
            flags, theme = load_theme(W)
            print('theme:', json.load(open(os.path.join(W, 'theme.json')))
                  ['theme'] if theme else 'legacy')
            vm_exe = os.path.join(W, 'demo_vm.exe')
            build.build_exe(vm_exe, [os.path.join(W, 'protected.c')],
                            link_flags=flags)
            if not args.nopepolish:
                print('pepolish:', pepolish.polish(vm_exe, theme=theme))
            a = build.run_exe(vm_exe, tries=3)
        except (RuntimeError, PermissionError, FileNotFoundError) as e:
            print('attempt %d blocked (%s), retrying...' % (k, type(e).__name__))
            time.sleep(0.6)
            continue
        open(os.path.join(W, 'vm_out.txt'), 'w').write(a.stdout)
        open(os.path.join(W, 'seed.txt'), 'w').write(str(seed))
        print('seed', seed, 'vm rc', a.returncode, 'plain rc', b.returncode)
        print('--- vm ---');    print(a.stdout, end='')
        print('--- plain ---'); print(b.stdout, end='')
        if a.returncode or b.returncode:
            print('EXIT FAILURE'); sys.exit(1)
        if a.stdout != b.stdout:
            print('!!! OUTPUT MISMATCH'); sys.exit(1)
        print('=== DEMO PASS: outputs identical ===')
        return
    print('all attempts blocked')
    sys.exit(1)


if __name__ == '__main__':
    main()
