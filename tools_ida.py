#!/usr/bin/env python3
"""Drive idalib against a binary and dump an analyst-style report:
segments, exports, imports, strings, function list, pseudocode of the
entry/main functions and the biggest functions (top N by size).

usage: python tools_ida.py <binary> <outreport.txt> [topN]
"""
import sys
import time


def main():
    import idapro
    binary, outp = sys.argv[1], sys.argv[2]
    topn = int(sys.argv[3]) if len(sys.argv) > 3 else 12

    t0 = time.time()
    r = idapro.open_database(binary, True)   # True = run auto-analysis
    lines = []
    P = lines.append
    P('=== idalib report: %s (open rc=%s, %.1fs) ===' % (binary, r, time.time() - t0))

    import idaapi
    import ida_segment
    import ida_entry
    import ida_funcs
    import ida_name
    import idautils
    import ida_bytes
    import ida_nalt

    P('\n--- segments ---')
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        P('%-10s %08X-%08X %s' % (ida_segment.get_segm_name(s), s.start_ea,
                                  s.end_ea, seg_perm(s)))

    P('\n--- entry points / exports ---')
    n = ida_entry.get_entry_qty()
    for i in range(min(n, 60)):
        ord_ = ida_entry.get_entry_ordinal(i)
        e = ida_entry.get_entry(ord_)
        nm = ida_entry.get_entry_name(ord_)
        P('%-28s %08X (ord %d)' % (nm or '?', e, ord_))

    P('\n--- imports (module: count) ---')
    imps = {}
    for i in range(ida_nalt.get_import_module_qty()):
        mod = ida_nalt.get_import_module_name(i)
        cnt = [0]

        def cb(ea, name, ord_, arg=cnt):
            arg[0] += 1
            if arg[0] <= 12:
                imps.setdefault(mod, []).append(name or '?')
            return True
        ida_nalt.enum_import_names(i, cb)
        imps.setdefault(mod, []).append('...(%d total)' % cnt[0])
    for mod, names in imps.items():
        P('%s: %s' % (mod, ', '.join(names[:14])))

    P('\n--- strings (first 80) ---')
    sc = 0
    for s in idautils.Strings():
        P(str(s))
        sc += 1
        if sc >= 80:
            break

    P('\n--- functions (%d) ---' % ida_funcs.get_func_qty())
    fs = []
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        if f:
            fs.append((ea, ida_name.get_name(ea) or 'sub_%X' % ea, f.size()))
    for ea, nm, sz in sorted(fs, key=lambda x: -x[2])[:40]:
        P('%08X %-30s %6d bytes' % (ea, nm, sz))

    # decompiler
    P('\n--- pseudocode ---')
    try:
        import ida_hexrays
        ok = ida_hexrays.init_hexrays_plugin()
        P('hexrays: %s' % ok)
        if ok:
            want = []
            # entry + main + start + biggest by size
            for nm in ('main', 'WinMain', 'start', '_main'):
                ea = ida_name.get_name_ea(idaapi.BADADDR, nm)
                if ea != idaapi.BADADDR:
                    want.append((nm, ea))
            for ea, nm, sz in sorted(fs, key=lambda x: -x[2])[:topn]:
                want.append((nm, ea))
            seen = set()
            for nm, ea in want:
                if ea in seen:
                    continue
                seen.add(ea)
                try:
                    cf = ida_hexrays.decompile(ea)
                    if cf:
                        P('\n===== %s @ %08X =====' % (nm, ea))
                        P(str(cf))
                except Exception as ex:
                    P('\n===== %s @ %08X ===== (decompile failed: %s)' % (nm, ea, ex))
    except Exception as ex:
        P('no hexrays: %s' % ex)

    open(outp, 'w', encoding='utf-8', errors='replace').write('\n'.join(lines))
    print('wrote', outp, len(lines), 'lines')
    idapro.close_database()


def seg_perm(s):
    import ida_segment
    p = ''
    if s.perm & ida_segment.SEGPERM_EXEC:
        p += 'X'
    if s.perm & ida_segment.SEGPERM_WRITE:
        p += 'W'
    if s.perm & ida_segment.SEGPERM_READ:
        p += 'R'
    return p


if __name__ == '__main__':
    main()
