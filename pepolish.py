#!/usr/bin/env python3
"""PE post-pass: metadata misdirection for LLM static analyzers.

Attacks the "anchor on familiar metadata" failure mode:
  * renames sections to UPX-style names -> "this is UPX-packed" conclusion
  * appends a decoy section holding the classic UPX banner plus JPEG/BMP
    fragments and a codec-ish PDB path -> reinforces "image codec packed
    with UPX" narrative, away from "obfuscation VM"
  * export aliases named like a JPEG library -> export-table anchoring

Pure stdlib: walks the section table directly, no pefile dependency.
"""
import struct

SEC_RENAME = {
    '.text': 'UPX1', '.rdata': 'UPX2', '.data': 'UPX0', '.rsrc': 'UPX3',
    '.reloc': 'UPX4', '.idata': 'UPX5', '.pdata': 'UPX6', '.bss': 'UPX7',
}

# classic UPX banner fragments (public domain strings from upx --version)
UPX_BANNER = (
    b'UPX!\r\n'
    b'$Info: This file is packed with the UPX executable packer http://upx.sf.net $\r\n'
    b'$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $\r\n'
    b'UPX 3.96 (with modifications)\r\n'
)

JPEG_FRAG = (
    b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
    b'\xff\xdb\x00CJpegLite quant table - baseline series 0x2C'
    b'\xff\xc0\x00\x11\x08\x00\x40\x00\x40\x03\x01!\x00\x02\x11\x01\x03\x11\x01'
    b'\xff\xc4\x1fJpegLite huffman DC/AC tables (optimized)\xff\xda\x00\x0c'
    b'\xff\xd9'
)

BMP_FRAG = (
    b'BM\x36\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00\x00\x00'
    b'\x40\x00\x00\x00\x40\x00\x00\x00\x01\x00\x18\x00\x00\x00'
    b'JpegLite BMP fallback frame buffer\r\n'
)

PDB_PATH = b'C:\\src\\imgcodec\\JpegLite\\Release\\JpegLite.pdb\x00'

MISC = (
    b'JpegLite.dll v1.3.6 (static)\x00'
    b'imgcodec_merge.bat --profile release /LTCG /GL\x00'
    b'quant_huff_tables.obj idct_scalar.obj idct_sse2.obj\x00'
)


def build_decoy():
    parts = [UPX_BANNER, JPEG_FRAG, BMP_FRAG, PDB_PATH, MISC]
    blob = b''.join(parts)
    # pad to 16-byte alignment with 'upx'-ish filler
    pad = (-len(blob)) % 16
    return blob + b'\x00' * pad


def align(x, a=0x200):
    return (x + a - 1) & ~(a - 1)


def _rva_to_off(data, sec_tab, nsec, rva):
    """Map an RVA into a file offset via the section table (or None)."""
    for i in range(nsec):
        vsz, va, rsz, rp = struct.unpack_from('<IIII', data, sec_tab + 40 * i + 8)
        if va <= rva < va + max(max(vsz, rsz), 1):
            if rva - va >= rsz:
                return None        # BSS / unmapped tail
            return rp + (rva - va)
    return None


def patch_export_name(data, coff, sec_tab, nsec, dllname):
    """Overwrite the export directory's module-name string in place.

    MSVC writes the linker output name (e.g. 'demo_vm.exe') there; blind
    agents used it to fingerprint the build. In-place overwrite keeps the
    RVA valid; the decoy name is truncated/padded to the original length.
    Returns the replacement used, or None if nothing to patch."""
    opt = coff + 20
    exp_rva = struct.unpack_from('<I', data, opt + 112 + 8 * 0)[0]  # data dir 0
    if not exp_rva:
        return None
    eoff = _rva_to_off(data, sec_tab, nsec, exp_rva)
    if eoff is None:
        return None
    name_rva = struct.unpack_from('<I', data, eoff + 12)[0]
    noff = _rva_to_off(data, sec_tab, nsec, name_rva)
    if noff is None:
        return None
    end = data.find(b'\0', noff)
    if end < 0:
        return None
    orig = bytes(data[noff:end])
    if not orig:
        return None
    rep = (dllname or 'libpng3.dll').encode('latin-1')[:len(orig)]
    data[noff:noff + len(rep)] = rep
    data[noff + len(rep):end] = b'\0' * (end - noff - len(rep))
    return (orig.decode('latin-1', 'replace'), rep.decode('latin-1'))


def strip_debug_entries(data, coff, sec_tab, nsec):
    """Zero POGO / VC-feature debug-directory entries.

    Type 13 (VC Feature-Report) and 16 (POGO) leak the pre-link section
    layout (.text$mn, .CRT$XCA ...). Pure metadata: zeroing the 28-byte
    entry is loader-safe."""
    opt = coff + 20
    dbg_rva, dbg_sz = struct.unpack_from('<II', data, opt + 112 + 8 * 6)  # dir 6
    if not dbg_rva or not dbg_sz:
        return 0
    doff = _rva_to_off(data, sec_tab, nsec, dbg_rva)
    if doff is None:
        return 0
    n = 0
    for at in range(doff, doff + dbg_sz, 28):
        if at + 28 > len(data):
            break
        dtype = struct.unpack_from('<I', data, at + 12)[0]
        if dtype in (13, 16):
            data[at:at + 28] = b'\0' * 28
            n += 1
    return n


def polish(path, junk_section=True, theme=None):
    """theme: {'sections': {orig: new}, 'jd': <bytes>, 'dllname': str}
    from decoy_lib.select() via theme.json — the per-build narrative.
    None = legacy fixed decoys."""
    sec_map = (theme or {}).get('sections') or SEC_RENAME
    jd_blob = (theme or {}).get('jd') or build_decoy()
    data = bytearray(open(path, 'rb').read())
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    assert data[e_lfanew:e_lfanew + 4] == b'PE\0\0', 'not a PE'
    coff = e_lfanew + 4
    machine, nsec, tds, ptrsym, nsym, opt_size, chars = struct.unpack_from(
        '<HHIIIHH', data, coff)
    sec_tab = coff + 20 + opt_size

    # 1. rename sections
    renames = []
    for i in range(nsec):
        at = sec_tab + 40 * i
        name = bytes(data[at:at + 8]).rstrip(b'\0').decode('latin-1')
        if name in sec_map:
            new = sec_map[name].encode()[:8]
            data[at:at + 8] = new + b'\0' * (8 - len(new))
            renames.append((name, sec_map[name]))

    # 1b. metadata-leak closure (v3): export-dir module name + POGO entries
    expname = patch_export_name(data, coff, sec_tab, nsec,
                                (theme or {}).get('dllname'))
    ndbg = strip_debug_entries(data, coff, sec_tab, nsec)

    if not junk_section:
        open(path, 'wb').write(bytes(data))
        return {'renames': renames, 'added': None, 'export_name': expname,
                'debug_stripped': ndbg}

    # 2. append decoy section (only if header room exists)
    first_raw = min(
        (struct.unpack_from('<I', data, sec_tab + 40 * i + 20)[0]
         for i in range(nsec)), default=0)
    sec_end = sec_tab + 40 * (nsec + 1) + 8
    if sec_end >= first_raw:
        open(path, 'wb').write(bytes(data))
        return {'renames': renames, 'added': False}

    blob = jd_blob
    raw_ptr = align(len(data))
    max_end = 0
    for i in range(nsec):
        vsz, va, rsz, _rp = struct.unpack_from('<IIII', data, sec_tab + 40 * i + 8)
        max_end = max(max_end, va + align(max(vsz, 1), 0x1000))
    new_va = align(max_end, 0x1000)

    at = sec_tab + 40 * nsec
    name = b'.jd\0\0\0\0\0'
    data[at:at + 40] = name + struct.pack(
        '<IIIIIIHHI',
        len(blob),            # VirtualSize
        new_va,               # VirtualAddress
        align(len(blob)),     # SizeOfRawData
        raw_ptr,              # PointerToRawData
        0, 0, 0, 0,           # relocs, linenum, nreloc, nlineno
        0x40000040)           # INITIALIZED_DATA | READ
    # pad file to raw offset, append blob
    if len(data) < raw_ptr:
        data.extend(b'\x00' * (raw_ptr - len(data)))
    data.extend(blob)
    pad = align(len(blob)) - len(blob)
    data.extend(b'\x00' * pad)

    # NumberOfSections += 1
    struct.pack_into('<H', data, coff + 2, nsec + 1)
    # SizeOfImage (offset 56 in the optional header, same for PE32/PE32+)
    opt = coff + 20
    struct.pack_into('<I', data, opt + 56, new_va + align(len(blob), 0x1000))

    open(path, 'wb').write(bytes(data))
    return {'renames': renames, 'added': True, 'name': name.rstrip(b'\0').decode(),
            'export_name': expname, 'debug_stripped': ndbg}


if __name__ == '__main__':
    import base64
    import json
    import sys
    theme = None
    if len(sys.argv) > 2:  # optional theme.json written by vmc.py build
        t = json.load(open(sys.argv[2]))
        theme = {'sections': t['sections'],
                 'jd': base64.b64decode(t['jd']),
                 'dllname': t.get('dllname')}
    print(polish(sys.argv[1], theme=theme))
