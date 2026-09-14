"""Independent grading check: verify the blind agents' folded key 0x2E336C8B
against the protected exe itself, without idalib.

Ground truth from codegen: masked blob-pointer records at VA 0x140024280/290/2A0/2B0
hold (true_ptr ^ mask) and the 256-entry handler table at 0x140023A60 holds
(handler_addr ^ mask). If a candidate mask is right, XOR-decoding must produce
the true blob pointers (0x140018800/18930/189F0/18A70) and handler addresses
inside the handler code region 0x140001000..0x140005100.

NOTE (REPORT.md 4.2): this check is expected to FAIL by construction — the
masked tables are only written at runtime by the init function, so the file
image holds unrelated bytes. Kept as the historical record of the failed
first attempt at grading the agents.
"""
import os
import struct

EXE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sample_alpha.exe')
IMG = 0x140000000
BLOB_PTRS = [0x140018800, 0x140018930, 0x1400189F0, 0x140018A70]
REC_VAS = [0x140024280, 0x140024290, 0x1400242A0, 0x1400242B0]
TBL_VA, TBL_N = 0x140023A60, 256
LO, HI = 0x140001000, 0x140005100
CANDS = [0x2E336C8B, 0x74DFAF35]  # agents' no-debugger / debugger folds

data = open(EXE, 'rb').read()
pe = struct.unpack_from('<I', data, 0x3C)[0]
nsec = struct.unpack_from('<H', data, pe + 6)[0]
opt = struct.unpack_from('<H', data, pe + 20)[0]
secs = []
for i in range(nsec):
    off = pe + 24 + opt + i * 40
    name = data[off:off + 8].rstrip(b'\0').decode('latin1')
    vsz, va, rsz, ro = struct.unpack_from('<IIII', data, off + 8)
    secs.append((name, va, max(vsz, rsz), ro))
    print('section %-8s va=%06x size=%x raw=%x' % (name, va, vsz, ro))

def foff(va):
    rva = va - IMG
    for name, sva, sz, ro in secs:
        if sva <= rva < sva + sz:
            return ro + (rva - sva)
    raise ValueError(hex(va))

print('\n-- blob-pointer records (stored ^ mask must equal true ptr) --')
for cand in CANDS:
    ok = 0
    for rec, true in zip(REC_VAS, BLOB_PTRS):
        stored = struct.unpack_from('<Q', data, foff(rec))[0]
        dec = stored ^ cand
        ok += dec == true
        print('mask %08X: rec %X -> %X (expect %X) %s'
              % (cand, rec, dec, true, 'OK' if dec == true else 'X'))
    if ok == 4:
        break

print('\n-- handler table: decoded entries inside %X..%X --' % (LO, HI))
for cand in CANDS:
    inside = 0
    for i in range(TBL_N):
        stored = struct.unpack_from('<Q', data, foff(TBL_VA + 8 * i))[0]
        if LO <= (stored ^ cand) < HI:
            inside += 1
    print('mask %08X: %d/%d entries in handler region' % (cand, inside, TBL_N))

print('\n-- derive TRUE mask = stored ^ true_ptr, check consistency --')
masks = set()
for rec, true in zip(REC_VAS, BLOB_PTRS):
    stored = struct.unpack_from('<Q', data, foff(rec))[0]
    masks.add(stored ^ true)
print('distinct masks over 4 blob records:', [hex(m) for m in masks])
if len(masks) == 1:
    true_mask = masks.pop()
    print('TRUE mask = 0x%016X (agents had 0x2E336C8B -> WRONG)' % true_mask)
    inside, uniq = 0, set()
    for i in range(TBL_N):
        stored = struct.unpack_from('<Q', data, foff(TBL_VA + 8 * i))[0]
        h = stored ^ true_mask
        if LO <= h < HI:
            inside += 1
            uniq.add(h)
    print('handler table with TRUE mask: %d/%d in region, %d distinct handlers'
          % (inside, TBL_N, len(uniq)))
