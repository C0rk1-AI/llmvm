import idapro
import os
import sys

binary = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sample_alpha.exe')
r = idapro.open_database(binary, True)

import idautils
import ida_funcs
import ida_bytes
import ida_name

# handler-code region observed in the masked table: sub_140001000 .. sub_140004F00
LO, HI = 0x140001000, 0x140005100
inrange = [ea for ea in idautils.Functions() if LO <= ea < HI]
allf = [ea for ea in idautils.Functions()]
print('total functions:', len(allf))
print('functions inside handler region 140001000-140005100:', len(inrange))

# how many of those are named (i.e. recognized as something) vs anonymous sub_
named = [ea for ea in inrange if not ida_name.get_name(ea).startswith('sub_')]
print('named in region:', len(named), [ida_name.get_name(ea) for ea in named[:10]])

# bytes in region not covered by any function -> invisible to the fn list
cov = 0
for ea in inrange:
    f = ida_funcs.get_func(ea)
    if f:
        cov += f.size()
print('region size: %d bytes, covered by functions: %d (%.0f%%)'
      % (HI - LO, cov, 100.0 * cov / (HI - LO)))

# the four bytecode blobs referenced by main (masked) - dump first bytes + look for terminators
for va, n in ((0x140018800, 512), (0x140018930, 512), (0x1400189F0, 512), (0x140018A70, 512)):
    b = ida_bytes.get_bytes(va, n)
    print('blob %08X[:48] = %s' % (va, b[:48].hex()))

idapro.close_database()
