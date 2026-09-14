"""Generate protected.c: polymorphic VM interpreter + wrappers + decoys.

v3 hardening (see REPORT.md §5.4) against the semantic-lift attack that
defeated v2 under the script-friendly protocol:
  * V3-a VM-in-VM: the operand-fetch / control-flow / KSET handlers are
    inner-VM bytecode programs (vmlib/inner.py), not native code — the ISA
    cannot be lifted by decompiling handlers, and nothing is verifiable
    until BOTH levels are re-hosted.
  * V3-b anti-canonicalization: every native handler gets a unique shape
    (interleaved junk, canceling tangles on live locals, opaque dual-path
    forms, helper splits) so "dump + canonical-form grouping" collapses to
    per-handler reads instead of ~75 shared forms.
  * V3-c fetch variants: several algebraically equivalent keystream fetch
    functions (different kmix form, lane algebra rewrites, combine
    parenthesization, byte-select form) are scattered across the interpreter
    and handlers — no single recovered formula text covers all fetch sites.

Layout of emitted file:
  [1] includes, vmst + globals
  [2] junk functions jn*
  [3] decoy functions dec_* (with fingerprint tables) + their return values
      mirrored in python for key assembly
  [4] bytecode / data-slot ciphertext arrays
  [5] kmix variants + dmx + outer fetch variants (V3-c)
  [6] inner VM: imst, inner scheme kmix, IMB, inner handlers, imx_run,
      inner program ciphertext arrays (V3-a)
  [7] 256 handlers (polymorphic shapes; innerized ops = trampolines)
  [8] host wrappers + host tables
  [9] vm_init: kload (decoys -> K1..K3/mk + inner keys, anti-debug) + tables
      + vmt + slots + inner dispatch table
  [10] vm_exec_core / vmx_run
  [11] wrappers for virtualized functions (original signatures)
  [12] #include user main
"""
from . import enc, inner
from .codegen import NFR, STK

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF

# set by emit() when trace=True — deep trace inside CALLH handler (debug builds)
TRACE_CALLH = ''

# outer semantics re-hosted as inner-VM programs (V3-a). Everything an
# analyst needs to DECODE the outer stream (operand fetch) or follow its
# control flow, plus the rekey op itself.
INNERIZED = ('PUSHI', 'PUSHD', 'LDFL', 'STFL', 'JMP', 'JT', 'JF', 'KSET')


def rotl(v, r):
    r &= 31
    v &= M32
    return ((v << r) | (v >> (32 - r))) & M32 if r else v


def u32(v):
    return v & M32


def cbytes(b, per=16):
    out = []
    for i in range(0, len(b), per):
        line = ','.join('0x%02x' % x for x in b[i:i + per])
        out.append(line + ',' if i + per < len(b) else line)
    return '\n'.join(out)


class Decoy:
    def __init__(self, name, code, value):
        self.name, self.code, self.value = name, code, value


# ---------------------------------------------------------------- decoys

def gen_decoys(rng):
    """Returns (list[Decoy], tables_c_code). Values mirrored exactly."""
    ds = []
    tbl = []

    # --- BMP header probe ---
    bmpd = [0x4D42, 0x0036, 0x0110, 0x0028, 0x0040, 0x0040,
            0x0001, 0x0018, 0x0000, 0x0F00]
    h = 0x4D42
    for i in range(10):
        h = u32(rotl(h ^ bmpd[i], (i & 7) + 1) + 0x4009)
    h ^= 0x1F
    tbl.append('static const uint32_t T_bmp[10] = {%s};'
               % ','.join('0x%08xu' % v for v in bmpd))
    ds.append(Decoy('dec_bmp_probe', '''uint32_t dec_bmp_probe(void){
    uint32_t h = 0x4D42u; unsigned i;
    for (i = 0; i < 10; i++) h = rotl(h ^ T_bmp[i], (i & 7u) + 1u) + 0x4009u;
    return h ^ 0x1Fu;
}''', h))

    # --- RLE scanline ---
    rled = [0x00, 0x05, 0x12, 0x00, 0x00, 0xFF, 0x03, 0x41, 0x42, 0x43,
            0x00, 0x00, 0x02, 0x7F, 0x00, 0x02]
    r = 0x00FF00FF
    for i in range(16):
        if rled[i] == 0xFF:
            r = u32(r + (rled[i] * (i + 3)))
        else:
            r = u32(r ^ (rled[i] + i) * 0x9D2C5680)
    tbl.append('static const unsigned char T_rle[16] = {%s};'
               % ','.join('0x%02x' % v for v in rled))
    ds.append(Decoy('dec_rle_scan', '''uint32_t dec_rle_scan(void){
    uint32_t r = 0x00FF00FFu; unsigned i;
    for (i = 0; i < 16; i++) {
        if (T_rle[i] == 0xFFu) r += T_rle[i] * (uint32_t)(i + 3u);
        else r ^= (T_rle[i] + (uint32_t)i) * 0x9D2C5680u;
    }
    return r;
}''', r))

    # --- JPEG IDCT-ish butterfly ---
    COSQ = [0x2D41, 0x3B21, 0x2D41, 0x187E, 0x2D41, 0x0C7E,
            0x2D41, 0x064E, 0x3B21, 0x2D41, 0x3B21, 0x0C7E]
    q = 0x00800000
    for i in range(12):
        q = u32((q >> 3) + COSQ[i] * (i + 1) + rotl(q, i & 15))
    tbl.append('static const uint32_t T_cos[12] = {%s};'
                % ','.join('0x%04xu' % v for v in COSQ))
    ds.append(Decoy('dec_jpeg_idct', '''uint32_t dec_jpeg_idct(void){
    uint32_t q = 0x00800000u; unsigned i;
    for (i = 0; i < 12; i++) q = (q >> 3) + T_cos[i] * (uint32_t)(i + 1u) + rotl(q, i & 15u);
    return q;
}''', q))

    # --- Huffman walk ---
    huff = [0x1F, 0x00, 0x11, 0x2F, 0x5D, 0x01, 0x00, 0x03,
            0x84, 0x1B, 0x77, 0x00, 0x0A, 0xC4, 0x1E, 0x2D,
            0x00, 0x09, 0x5B, 0x31, 0x62, 0x00, 0x00, 0x48]
    w = 0x0000ABCD
    for i in range(24):
        if huff[i]:
            w = u32(rotl(w, huff[i] & 7) + huff[i])
        else:
            w = u32(w ^ 0x61C88647)
    tbl.append('static const unsigned char T_huf[24] = {%s};'
                % ','.join('0x%02x' % v for v in huff))
    ds.append(Decoy('dec_huff_walk', '''uint32_t dec_huff_walk(void){
    uint32_t w = 0x0000ABCDu; unsigned i;
    for (i = 0; i < 24; i++) {
        if (T_huf[i]) w = rotl(w, T_huf[i] & 7u) + T_huf[i];
        else w ^= 0x61C88647u;
    }
    return w;
}''', w))

    # --- MD5-ish mix (fingerprint constants) ---
    m = 0x67452301
    md5k = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501]
    for i in range(8):
        b = (0xEFCDAB89 + md5k[i]) & M32
        m = u32(rotl(m ^ b, 7) + md5k[i] + i)
    tbl.append('static const uint32_t T_md5[8] = {%s};'
               % ','.join('0x%08xu' % v for v in md5k))
    ds.append(Decoy('dec_md5_mix', '''uint32_t dec_md5_mix(void){
    uint32_t m = 0x67452301u, b; unsigned i;
    for (i = 0; i < 8; i++) { b = 0xEFCDAB89u + T_md5[i]; m = rotl(m ^ b, 7u) + T_md5[i] + (uint32_t)i; }
    return m;
}''', m))

    # --- quantization table check (standard luminance matrix fingerprint) ---
    QMT = [16, 11, 10, 16, 24, 40, 51, 61,
           12, 12, 14, 19, 26, 58, 60, 55,
           14, 13, 16, 24, 40, 57, 69, 56,
           14, 17, 22, 29, 51, 87, 80, 62,
           18, 22, 37, 56, 68, 109, 103, 77,
           24, 35, 55, 64, 81, 104, 113, 92,
           49, 64, 78, 87, 103, 121, 120, 101,
           72, 92, 95, 98, 112, 100, 103, 99]
    s = 0
    for i in range(64):
        s += QMT[i] * (i + 1)
    s = u32((s & 0xFFFF) ^ rotl(s & 0xFFFF, 11) + 0x2C1B)
    tbl.append('static const unsigned char T_qmt[64] = {%s};'
                % ','.join(str(v) for v in QMT))
    ds.append(Decoy('dec_quant_check', '''uint32_t dec_quant_check(void){
    uint32_t s = 0u; unsigned i;
    for (i = 0; i < 64; i++) s += T_qmt[i] * (uint32_t)(i + 1u);
    return (s & 0xFFFFu) ^ (rotl(s & 0xFFFFu, 11u) + 0x2C1Bu);
}''', s))

    # --- CRC32 (real table -> strong fingerprint) ---
    crc_tab = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
        crc_tab.append(c & M32)
    c0 = 0xFFFFFFFF
    for i in range(16):
        c0 = (c0 >> 8) ^ crc_tab[(c0 ^ bytes(range(16))[i]) & 0xFF]
    c0 ^= 0xFFFFFFFF
    tbl.append('static const uint32_t T_crc[256] = {%s};' %
               ','.join('0x%08xu' % v for v in crc_tab))
    ds.append(Decoy('dec_png_crc', '''uint32_t dec_png_crc(void){
    uint32_t c = 0xFFFFFFFFu; static const unsigned char P[16] =
        {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}; unsigned i;
    for (i = 0; i < 16; i++) c = (c >> 8) ^ T_crc[(c ^ P[i]) & 0xFFu];
    return c ^ 0xFFFFFFFFu;
}''', c0 & M32))

    rng.shuffle(ds)
    return ds, tbl


# ---------------------------------------------------------------- V3-c: fetch variants

def fetch_variant(rng, sch, name, stream, keys, pos, tail, kmix_fns,
                  sig='vmst *s', retty='unsigned char', ret='return %s;'):
    """One full fetch function computing
        byte = stream[p] ^ (uint8_t)(ks8(p) >> sh)
    with a randomly chosen but bit-exact algebra (u32 lanes throughout, so
    C wrapping matches enc.Scheme.ks8). `tail` runs after the fetch (pc/pp/lp
    updates) and must not touch the byte temp. Lane COMBINE grouping is
    never permuted across the scheme's '+' pair — only textual rewrites."""
    t = rng.choice(('b9', 'rb', 'ob', 'cx', 'qb'))
    names = rng.sample(('t1', 't2', 't3', 'u1', 'u2', 'u3', 'w1', 'w2'), 3)
    pc1 = '0x%08xu' % sch.pc1
    l1in = rng.choice(['p * %s' % pc1, '(p * %s)' % pc1])
    l3in = rng.choice([
        'rotl(p, %du)' % sch.rot,
        '((p << %du) | (p >> %du))' % (sch.rot, 32 - sch.rot)])

    def lane(key, pin, want):
        fn = rng.choice(kmix_fns)
        r = rng.random()
        if want == '+' and r < 0.3:
            # k + a == (k ^ a) + 2*(k & a)   [u32-exact full-adder split]
            return '%s((%s ^ (%s)) + ((%s & (%s)) << 1u))' % (
                fn, key, pin, key, pin)
        if want == '^' and r < 0.3:
            # k ^ a == (k + a) - 2*(k & a)   [u32-exact]
            return '%s(((%s + (%s)) - ((%s & (%s)) << 1u)))' % (
                fn, key, pin, key, pin)
        return '%s(%s %s (%s))' % (fn, key, want, pin)

    lanes = [lane(keys[0], l1in, sch.l1),
             lane(keys[1], 'p', sch.l2),
             lane(keys[2], l3in, sch.l3)]
    order = [0, 1, 2]
    rng.shuffle(order)
    holder = {}                      # lane index -> assigned temp name
    for i, li in enumerate(order):
        holder[li] = names[i]
    stmts = ['    uint32_t %s = %s;' % (holder[li], lanes[li])
             for li in order]
    X, Y, Z = holder[0], holder[1], holder[2]
    if sch.cmb == 0:
        cmb = rng.choice(['(%s ^ %s) ^ %s' % (X, Y, Z),
                          '%s ^ (%s ^ %s)' % (X, Y, Z),
                          '(%s ^ %s) ^ %s' % (X, Z, Y)])
    elif sch.cmb == 1:               # (x + y) ^ z — the '+' pair stays put
        cmb = rng.choice(['(%s + %s) ^ %s' % (X, Y, Z),
                          '%s ^ (%s + %s)' % (Z, X, Y)])
    else:                            # x ^ (y + z)
        cmb = rng.choice(['%s ^ (%s + %s)' % (X, Y, Z),
                          '(%s + %s) ^ %s' % (Y, Z, X)])
    sel = rng.choice(['(unsigned char)((%s) >> %du)' % (cmb, sch.sh),
                      '(((%s) >> %du) & 0xFFu)' % (cmb, sch.sh)])
    return '''static %s %s(%s){
    unsigned int p = %s;
%s
    unsigned char %s = (unsigned char)(%s[p] ^ (unsigned char)(%s));
%s
    %s
}''' % (retty, name, sig, pos, '\n'.join(stmts), t, stream, sel, tail,
        ret % t)


def kmix_variants(rng, sch, prefix):
    """Canonical kmix + one split-multiply rewrite (u32-exact: M = 2^k + r,
    so x*M == (x<<k) + x*r)."""
    canon = ('static uint32_t %s(uint32_t x){\n'
             '    x ^= x >> %du; x *= 0x%08xu; x ^= x >> %du; '
             'x *= 0x%08xu; return x ^ (x >> %du);\n}'
             % (prefix, sch.kms1, sch.kmm1, sch.kms2, sch.kmm2, sch.kms3))
    k = sch.kmm1.bit_length() - 1
    r1 = sch.kmm1 - (1 << k)
    k2 = sch.kmm2.bit_length() - 1
    r2 = sch.kmm2 - (1 << k2)
    tmp = rng.choice(('q', 'g', 'h'))
    alt = ('static uint32_t %s2(uint32_t x){\n'
           '    uint32_t %s = x ^ (x >> %du);\n'
           '    %s = (%s << %du) + %s * 0x%08xu;\n'
           '    %s ^= %s >> %du;\n'
           '    %s = (%s << %du) + %s * 0x%08xu;\n'
           '    return %s ^ (%s >> %du);\n'
           '}'
           % (prefix, tmp, sch.kms1,
              tmp, tmp, k, tmp, r1,
              tmp, tmp, sch.kms2,
              tmp, tmp, k2, tmp, r2,
              tmp, tmp, sch.kms3))
    return canon + '\n' + alt


# ---------------------------------------------------------------- V3-b: handler shapes

def hname(rng, used, prefix='h_'):
    while True:
        n = '%s%04x' % (prefix, rng.randrange(0x10000))
        if n not in used:
            used.add(n)
            return n


def junklines(rng, count=1):
    out = []
    for _ in range(count):
        k = rng.randrange(4)
        if k == 0:
            out.append('    s->fr[%d] ^= 0x%016xull;'
                       % (60 + rng.randrange(4), rng.getrandbits(64)))
        elif k == 1:
            out.append('    jn%d();' % rng.randrange(4))
        elif k == 2:
            out.append('    s->fr[%d] += (uint64_t)s->pp * %dull;'
                       % (60 + rng.randrange(4), rng.randrange(2, 97)))
        else:
            # harmless-if: scratch-reg side work gated on a runtime value —
            # not trivially provable dead, costs dataflow analysis to dismiss
            out.append('    if (((unsigned)s->sp ^ G_k%d ^ 0x%08xu) == 0u) '
                       '{ s->fr[%d] ^= (uint64_t)s->pp * %dull; }'
                       % (rng.randrange(1, 4), rng.getrandbits(32),
                          60 + rng.randrange(4), rng.randrange(2, 200)))
    return '\n'.join(out)


def opaque_cond(rng):
    """Runtime-dependent condition (both arms equivalent where used)."""
    return rng.choice([
        '(((unsigned)s->pc ^ G_k%d) & 1u) == 0u' % rng.randrange(1, 4),
        '(((unsigned)s->pp ^ G_k%d) & 3u) < 2u' % rng.randrange(1, 4),
        '((s->sp ^ (int)G_k%d) & 1u) != 0u' % rng.randrange(1, 4),
    ])


def _weave(rng, lines):
    """Interleave junk between real statements."""
    out = []
    for i, ln in enumerate(lines):
        out.append(ln)
        if i < len(lines) - 1 and rng.random() < 0.45:
            out.append(junklines(rng, 1))
    return out


def gen_binop_expr(rng, op, a='v1', b='v2'):
    T = {
        'ADD': ['%s + %s', '%s - (uint64_t)(0 - %s)',
                '(%s ^ %s) + ((%s & %s) << 1)', '(%s | %s) + (%s & %s)'],
        'SUB': ['%s - %s', '%s + (uint64_t)(0 - %s)', '~(~%s + %s)',
                '(%s ^ %s) - ((~%s & %s) << 1)'],
        'MUL': ['%s * %s'],
        'AND': ['%s & %s', '~(~%s | ~%s)', '(%s | %s) ^ (%s ^ %s)'],
        'OR':  ['%s | %s', '~(~%s & ~%s)', '(%s & %s) + (%s ^ %s)'],
        'XOR': ['%s ^ %s', '(%s | %s) & ~( %s & %s)',
                '(~%s & %s) | (%s & ~%s)', '(%s | %s) - (%s & %s)'],
    }
    if op in T:
        f = rng.choice(T[op])
        c = f.count('%s')
        return f % {2: (a, b), 3: (a, b, a), 4: (a, b, a, b)}[c]
    if op == 'DIVU':
        return '%s / %s' % (a, b)
    if op == 'MODU':
        return '%s %% %s' % (a, b)
    if op == 'DIVS':
        return '(uint64_t)((int64_t)%s / (int64_t)%s)' % (a, b)
    if op == 'MODS':
        return '(uint64_t)((int64_t)%s %% (int64_t)%s)' % (a, b)
    if op == 'SHL':
        return '%s << (%s & 63u)' % (a, b)
    if op == 'SHR':
        return '%s >> (%s & 63u)' % (a, b)
    if op == 'SAR':
        return '(uint64_t)((int64_t)%s >> (%s & 63u))' % (a, b)
    # NB: the classic "(a-b)>>63" borrow trick is NOT an identity for all
    # u64 pairs (fails e.g. a=0,b=UINT64_MAX). The sign-bias form below is
    # exact: unsigned a<b  <=>  signed (a^MSB) < (b^MSB).
    cmp_u = {
        'LTU': ['(%s < %s)',
                '((int64_t)(%s ^ 0x8000000000000000ull) < '
                '(int64_t)(%s ^ 0x8000000000000000ull))'],
        'LEQU': ['(%s <= %s)',
                 '((int64_t)(%s ^ 0x8000000000000000ull) <= '
                 '(int64_t)(%s ^ 0x8000000000000000ull))'],
        'GTU': ['(%s > %s)',
                '((int64_t)(%s ^ 0x8000000000000000ull) > '
                '(int64_t)(%s ^ 0x8000000000000000ull))'],
        'GEQU': ['(%s >= %s)',
                 '((int64_t)(%s ^ 0x8000000000000000ull) >= '
                 '(int64_t)(%s ^ 0x8000000000000000ull))'],
    }
    if op in cmp_u:
        f = rng.choice(cmp_u[op])
        if f.count('%s') == 4:
            return '(uint64_t)' + f % (a, b, a, b)
        return '(uint64_t)' + f % (a, b)
    cmp_s = {'LTS': '(%s < %s)', 'LEQS': '(%s <= %s)',
             'GTS': '(%s > %s)', 'GEQS': '(%s >= %s)'}
    if op in cmp_s:
        return '(uint64_t)((int64_t)%s %s (int64_t)%s)' % (
            a, {'LTS': '<', 'LEQS': '<=', 'GTS': '>', 'GEQS': '>='}[op], b)
    if op == 'EQU':
        if rng.randrange(2):
            return '(%s == %s)' % (a, b)
        return '(uint64_t)((%s ^ %s) == 0)' % (a, b)
    if op == 'NEQ':
        if rng.randrange(2):
            return '(%s != %s)' % (a, b)
        return '(uint64_t)((%s ^ %s) != 0)' % (a, b)
    raise KeyError(op)


def _two_forms(rng, op, a, b):
    """Up to two distinct exact expressions for op (opaque dual-path arms).
    Single-form ops (MUL, DIV*) yield one entry and the caller falls back."""
    seen = []
    for _ in range(12):
        e = gen_binop_expr(rng, op, a, b)
        if e not in seen:
            seen.append(e)
        if len(seen) == 2:
            break
    return seen


def gen_binop_handler(rng, used, op, helpers):
    """V3-b binop: inline / opaque dual-path / helper-split shape, junk
    interleave, and a canceling tangle on the live result whose USE is
    compensated (`rr ^= K; ...; push rr ^ K; rr ^= K;`) — stripping one
    half of the pair silently corrupts semantics."""
    n = hname(rng, used)
    va, vb, vr = rng.sample(('v1', 'v2', 'rr', 'ta', 'tb', 'q1', 'q2'), 3)
    pops = ('    uint64_t %s = s->st[--s->sp];\n'
            '    uint64_t %s = s->st[--s->sp];' % (vb, va))
    shape = rng.randrange(3)
    forms = _two_forms(rng, op, va, vb) if shape == 1 else []
    if shape == 1 and len(forms) < 2:
        shape = 0
    if shape == 0:
        core = ['    uint64_t %s = %s;'
                % (vr, gen_binop_expr(rng, op, va, vb))]
    elif shape == 1:
        core = ['    uint64_t %s;' % vr,
                '    if (%s) { %s = %s; } else { %s = %s; }'
                % (opaque_cond(rng), vr, forms[0], vr, forms[1])]
    else:
        hn = hname(rng, used, 'hc_')
        helpers.append('static uint64_t %s(uint64_t a, uint64_t b){ '
                       'return (uint64_t)(%s); }'
                       % (hn, gen_binop_expr(rng, op, 'a', 'b')))
        core = ['    uint64_t %s = %s(%s, %s);' % (vr, hn, va, vb)]
    lines = [pops] + core
    if rng.random() < 0.35:
        kk = '0x%016xull' % rng.getrandbits(64)
        lines += ['    %s ^= %s;' % (vr, kk),
                  junklines(rng, 1),
                  '    s->st[s->sp++] = %s ^ %s;' % (vr, kk),
                  '    %s ^= %s;' % (vr, kk)]
    else:
        lines.append('    s->st[s->sp++] = %s;' % vr)
    body = '\n'.join(_weave(rng, lines))
    return n, 'static void %s(vmst *s){ (void)s;\n%s\n}' % (n, body)


def gen_handler(rng, used, op, sch=None, fx=None, helpers=None):
    """fx: fetch-name set {b,w32,w32s,w64} chosen per handler (V3-c)."""
    helpers = helpers if helpers is not None else []
    fx = fx or {'b': 'NXB', 'w32': 'NX32', 'w32s': 'NX32S', 'w64': 'NX64'}
    binops = {'ADD', 'SUB', 'MUL', 'AND', 'OR', 'XOR', 'DIVU', 'MODU',
              'DIVS', 'MODS', 'SHL', 'SHR', 'SAR',
              'LTU', 'LEQU', 'GTU', 'GEQU', 'LTS', 'LEQS', 'GTS', 'GEQS',
              'EQU', 'NEQ'}
    unops = {'NEG', 'BNOT', 'NOTL'}
    if op in binops:
        return gen_binop_handler(rng, used, op, helpers)
    n = hname(rng, used)
    if op in unops:
        if op == 'NEG':
            forms = ['(uint64_t)(0 - %s)', '(~%s + 1ull)']
        elif op == 'BNOT':
            forms = ['~%s', '%s ^ 0xFFFFFFFFFFFFFFFFull']
        else:
            forms = ['(uint64_t)(%s == 0)', '(uint64_t)!%s']
        va, vr = rng.sample(('v1', 'rr', 'u1', 'w1'), 2)
        lines = ['    uint64_t %s = s->st[--s->sp];' % va]
        if rng.random() < 0.5:
            eA = (forms[0] % va) if '%s' in forms[0] else forms[0].replace('v1', va)
            eB = (forms[1] % va) if '%s' in forms[1] else forms[1].replace('v1', va)
            lines.append('    uint64_t %s;' % vr)
            lines.append('    if (%s) { %s = %s; } else { %s = %s; }'
                         % (opaque_cond(rng), vr, eA, vr, eB))
        else:
            e = rng.choice(forms)
            lines.append('    uint64_t %s = %s;'
                         % (vr, (e % va) if '%s' in e else e.replace('v1', va)))
        lines.append('    s->st[s->sp++] = %s;' % vr)
        body = '\n'.join(_weave(rng, lines))
    elif op in ('TRU8', 'TRU16', 'TRU32'):
        ct = {'TRU8': 'uint8_t', 'TRU16': 'uint16_t', 'TRU32': 'uint32_t'}[op]
        va, vr = rng.sample(('v1', 'rr', 'u2', 'w2'), 2)
        lines = ['    uint64_t %s = s->st[--s->sp];' % va,
                 '    uint64_t %s = (uint64_t)(%s)%s;' % (vr, ct, va),
                 '    s->st[s->sp++] = %s;' % vr]
        body = '\n'.join(_weave(rng, lines))
    elif op == 'DUP':
        lines = ['    s->st[s->sp] = s->st[s->sp - 1];', '    s->sp++;']
        body = '\n'.join(_weave(rng, lines))
    elif op == 'POP':
        body = junklines(rng, rng.randrange(1, 3)) + '\n    s->sp--;'
    elif op == 'SWAP':
        a, = rng.sample(('ta', 'tb', 't1', 't2'), 1)
        lines = ['    uint64_t %s = s->st[s->sp - 1];' % a,
                 '    s->st[s->sp - 1] = s->st[s->sp - 2];',
                 '    s->st[s->sp - 2] = %s;' % a]
        body = '\n'.join(_weave(rng, lines))
    elif op in ('LD8', 'LD16', 'LD32', 'LD64'):
        ct = {'LD8': 'uint8_t', 'LD16': 'uint16_t',
              'LD32': 'uint32_t', 'LD64': 'uint64_t'}[op]
        va, vr = rng.sample(('ad', 'rr', 'p1', 'q1'), 2)
        lines = ['    uint64_t %s = s->st[--s->sp];' % va,
                 '    uint64_t %s = (uint64_t)*(%s *)(uintptr_t)%s;'
                 % (vr, ct, va),
                 '    s->st[s->sp++] = %s;' % vr]
        body = '\n'.join(_weave(rng, lines))
    elif op in ('ST8', 'ST16', 'ST32', 'ST64'):
        ct = {'ST8': 'uint8_t', 'ST16': 'uint16_t',
              'ST32': 'uint32_t', 'ST64': 'uint64_t'}[op]
        vv, ad = rng.sample(('vv', 'ad', 'q3', 'p2'), 2)
        lines = ['    uint64_t %s = s->st[--s->sp];' % vv,
                 '    uint64_t %s = s->st[--s->sp];' % ad,
                 '    *(%s *)(uintptr_t)%s = (%s)%s;' % (ct, ad, ct, vv)]
        body = '\n'.join(_weave(rng, lines))
    elif op == 'CALLH':
        body = ('    unsigned char o0 = %s(s); unsigned char q = '
                '(unsigned char)(o0 ^ dmx(s->lp));\n'
                '    unsigned char na = G_harn[q]; uint64_t av[3]; '
                'unsigned char aj;\n'
                '    av[0] = 0; av[1] = 0; av[2] = 0;\n'
                '%s\n'
                '    for (aj = na; aj > 0; aj--) av[aj - 1] = s->st[--s->sp];\n'
                '    uint64_t (*hf)(uint64_t, uint64_t, uint64_t) =\n'
                '        (uint64_t (*)(uint64_t, uint64_t, uint64_t))'
                '(G_host[q] ^ (uint64_t)G_mk);\n'
                '%s\n'
                '    s->st[s->sp++] = hf(av[0], av[1], av[2]);'
                % (fx['b'], junklines(rng, 1), TRACE_CALLH))
    elif op == 'CALLV':
        body = ('    unsigned char o9 = %s(s); unsigned char q = '
                '(unsigned char)(o9 ^ dmx(s->lp));\n'
                '    const unsigned char *bc2 = (const unsigned char *)'
                '(G_vmt[q].bcp ^ (uint64_t)G_mk);\n'
                '    unsigned char na = G_vmt[q].na; uint64_t rr[3]; '
                'rr[0] = rr[1] = rr[2] = 0;\n'
                '%s\n'
                '    while (na > 0) { rr[--na] = s->st[--s->sp]; }\n'
                '    vm_exec_core(bc2, G_vmt[q].n, G_vmt[q].na, rr);\n'
                '    s->st[s->sp++] = rr[0];' % (fx['b'], junklines(rng, 1)))
    elif op == 'RET':
        body = junklines(rng, 2) + '\n    s->alive = 0;'
    elif op == 'NOP':
        body = junklines(rng, 2)
    else:  # poison — V3-b: several shapes so the ~171 landmines do not all
        # share one canonical form
        k = rng.getrandbits(64)
        shape = rng.randrange(3)
        if shape == 0:
            body = ('    s->alive = 0; s->sp = 0; '
                    's->fr[0] ^= 0x%016xull;' % k)
        elif shape == 1:
            body = ('    s->sp = 0; s->alive = 0; '
                    's->fr[0] = s->fr[0] ^ 0x%016xull;\n%s'
                    % (k, junklines(rng, 1)))
        else:
            body = ('    if (%s) { s->alive = 0; s->sp = 0; }\n'
                    '    else { s->sp = 0; s->alive = 0; }\n'
                    '    s->fr[0] ^= 0x%016xull;\n%s'
                    % (opaque_cond(rng), k, junklines(rng, 1)))
    return n, 'static void %s(vmst *s){ (void)s;\n%s\n}' % (n, body)


# ---------------------------------------------------------------- V3-a: inner build

class InnerBuild:
    """Draws the inner scheme/keys/opcode map and assembles one encrypted
    program per INNERIZED outer alias. Inner keys G_i1..3 are independent of
    the outer KSET (an inner program must decode identically no matter when
    its outer handler fires — loops revisit outer positions)."""

    def __init__(self, ctx):
        rng = ctx.rng
        self.isch = enc.Scheme(rng)
        self.I1 = rng.getrandbits(32)
        self.I2 = rng.getrandbits(32)
        self.I3 = rng.getrandbits(32)
        self.IMK = rng.getrandbits(32) | 0x10000
        self.imap = inner.draw_imap(rng)
        # one distinct program per outer alias opcode (ctx.aliases maps
        # semantic op -> list of opcode bytes)
        self.programs = {}     # outer opcode byte -> cipher bytes
        for sem in INNERIZED:
            for byte in ctx.aliases[sem]:
                p = inner.program_for(sem, rng, ctx.sch.kset)
                plain = inner.linearize(p, self.imap, rng)
                cip = bytes(b ^ self.isch.ks8(i, self.I1, self.I2, self.I3)
                            for i, b in enumerate(plain))
                self.programs[byte] = cip


IMB_HELPERS = '''
static uint64_t IMB64(imst *m){
    uint64_t r = 0; int i;
    for (i = 0; i < 8; i++) r |= (uint64_t)IMB(m) << (8 * i);
    return r;
}
static int32_t IMB16S(imst *m){
    uint32_t r = 0; int i;
    for (i = 0; i < 2; i++) r |= (uint32_t)IMB(m) << (8 * i);
    return (int32_t)(int16_t)(uint16_t)r;
}
'''


def emit_inner_c(ib, rng, osch):
    """C text for the inner VM + (byte -> handler name) map for G_it."""
    isch = ib.isch
    L = []
    A = L.append
    A('''
/* ---- inner VM (V3-a): outer fetch/flow/rekey ops live here as data ---- */
typedef struct _imst {
    const unsigned char *ip; uint32_t pc; uint64_t v[8]; int sp;
    uint64_t scr; uint64_t jj; int alive;
} imst;
typedef void (*imhf)(imst *, vmst *);
static uint32_t G_i1, G_i2, G_i3;
static uint64_t G_imk;
static uintptr_t G_it[256];''')
    A(kmix_variants(rng, isch, 'ikm'))
    # inner fetch: decrypts the inner stream with the INNER scheme
    A(fetch_variant(rng, isch, 'IMB', 'm->ip', ('G_i1', 'G_i2', 'G_i3'),
                    'm->pc', '    m->pc++;', ('ikm', 'ikm2'),
                    sig='imst *m'))
    A(IMB_HELPERS)
    # one handler per mapped inner opcode byte, polymorphic (V3-b)
    used = set()
    byte_name = {}
    bodies = []
    for sem in inner.INNER_OPS:
        for b in ib.imap[sem]:
            n = hname(rng, used, 'g_')
            byte_name[b] = n
            bodies.append(_inner_handler_c(rng, sem, n, osch))
    A('\n'.join(bodies))
    A('''
static void imx_run(const unsigned char *p, vmst *s){
    imst m;
    m.ip = p; m.pc = 0; m.sp = 0; m.scr = 0; m.jj = 0; m.alive = 1;
    while (m.alive) {
        unsigned char op = IMB(&m);
        ((imhf)(G_it[op] ^ (uint64_t)G_imk))(&m, s);
    }
}''')
    return '\n'.join(L), byte_name


def _inner_handler_c(rng, sem, n, osch):
    """One inner handler: small polymorphic body + junk. IOLDB carries a
    variant of the OUTER keystream (it decrypts the outer stream)."""
    jl = junklines_im(rng)
    va, vb = rng.sample(('a', 'b', 'x', 'y', 'd', 'e'), 2)
    B = {
        'IPUSH': '    m->v[m->sp++] = IMB64(m);',
        'IPOP': '    m->sp--;',
        'IDUP': '    m->v[m->sp] = m->v[m->sp - 1]; m->sp++;',
        'ISWAP': ('    uint64_t %s = m->v[m->sp - 1]; m->v[m->sp - 1] = '
                  'm->v[m->sp - 2]; m->v[m->sp - 2] = %s;' % (va, va)),
        'ISAVE': '    m->scr = m->v[--m->sp];',
        'ILOAD': '    m->v[m->sp++] = m->scr;',
        'IADD': _ibin(rng, '+', va, vb),
        'ISUB': _ibin(rng, '-', va, vb),
        'IMUL': _ibin(rng, '*', va, vb),
        'IXOR': _ibin(rng, '^', va, vb),
        'IAND': _ibin(rng, '&', va, vb),
        'IOR': _ibin(rng, '|', va, vb),
        'ISHL': '    m->v[m->sp - 2] = m->v[m->sp - 2] << (m->v[m->sp - 1] & 63u); m->sp--;',
        'ISHR': '    m->v[m->sp - 2] = m->v[m->sp - 2] >> (m->v[m->sp - 1] & 63u); m->sp--;',
        'ISAR': '    m->v[m->sp - 2] = (uint64_t)((int64_t)m->v[m->sp - 2] >> (m->v[m->sp - 1] & 63u)); m->sp--;',
        'INEG': '    m->v[m->sp - 1] = (uint64_t)(0 - m->v[m->sp - 1]);',
        'IBNOT': '    m->v[m->sp - 1] = ~m->v[m->sp - 1];',
        'INOTL': '    m->v[m->sp - 1] = (uint64_t)(m->v[m->sp - 1] == 0);',
        'IMASK32': '    m->v[m->sp - 1] &= 0xFFFFFFFFu;',
        'ISEXT32': '    m->v[m->sp - 1] = (uint64_t)(int64_t)(int32_t)(uint32_t)m->v[m->sp - 1];',
        'IROL32': '    m->v[m->sp - 1] = rotl((uint32_t)m->v[m->sp - 1], IMB(m));',
        'IOS_PUSH': '    s->st[s->sp++] = m->v[--m->sp];',
        'IOS_POP': '    m->v[m->sp++] = s->st[--s->sp];',
        'IOF_GETD': '    { unsigned char q = (unsigned char)m->v[--m->sp]; m->v[m->sp++] = s->fr[q & %du]; }' % (NFR - 1),
        'IOF_SETD': '    { uint64_t val = m->v[--m->sp]; unsigned char q = (unsigned char)m->v[--m->sp]; s->fr[q & %du] = val; }' % (NFR - 1),
        'IGETDB': '    { unsigned char q = (unsigned char)m->v[--m->sp]; m->v[m->sp++] = (uint64_t)(uintptr_t)G_db[q]; }',
        'IDXMX': '    m->v[m->sp - 1] ^= (uint64_t)dmx(s->lp);',
        'IGETLP': '    m->v[m->sp++] = (uint64_t)s->lp;',
        'IPC_GET': '    m->v[m->sp++] = (uint64_t)s->pc;',
        'IPC_SET': '    s->pc = (uint32_t)m->v[--m->sp];',
        'ICTEST': '    { uint32_t t = (uint32_t)m->v[--m->sp]; if (m->v[--m->sp]) s->pc = t; }',
        'ICFTEST': '    { uint32_t t = (uint32_t)m->v[--m->sp]; if (!m->v[--m->sp]) s->pc = t; }',
        'IKEY_GET1': '    m->v[m->sp++] = (uint64_t)G_k1;',
        'IKEY_GET2': '    m->v[m->sp++] = (uint64_t)G_k2;',
        'IKEY_GET3': '    m->v[m->sp++] = (uint64_t)G_k3;',
        'IKEY_SET1': '    G_k1 = (uint32_t)m->v[--m->sp];',
        'IKEY_SET2': '    G_k2 = (uint32_t)m->v[--m->sp];',
        'IKEY_SET3': '    G_k3 = (uint32_t)m->v[--m->sp];',
        'IJMP': '    m->pc = (uint32_t)((int32_t)m->pc + IMB16S(m));',
        'IJT': '    { int32_t r = IMB16S(m); if (m->v[--m->sp]) m->pc = (uint32_t)((int32_t)m->pc + r); }',
        'IJF': '    { int32_t r = IMB16S(m); if (!m->v[--m->sp]) m->pc = (uint32_t)((int32_t)m->pc + r); }',
        'IRET': '    m->alive = 0;',
    }
    if sem == 'IOLDB':
        # fetch+decrypt the NEXT OUTER stream byte, push it on the inner
        # stack. The outer keystream (current G_k*, outer scheme) is inlined
        # as one of the V3-c variants.
        return fetch_variant(rng, osch, n, 's->bc',
                             ('G_k1', 'G_k2', 'G_k3'), 's->pc',
                             '    s->pc++; s->pp++; s->lp = p;',
                             ('km', 'km2'),
                             sig='imst *m, vmst *s', retty='void',
                             ret='m->v[m->sp++] = %s;')
    core = B[sem]
    return 'static void %s(imst *m, vmst *s){ (void)m; (void)s;\n%s\n%s\n}' % (
        n, core, jl)


def _ibin(rng, o, va, vb):
    if rng.random() < 0.5:
        return ('    uint64_t %s = m->v[--m->sp]; uint64_t %s = m->v[--m->sp];\n'
                '    m->v[m->sp++] = %s %s %s;' % (vb, va, va, o, vb))
    return ('    m->v[m->sp - 2] = m->v[m->sp - 2] %s m->v[m->sp - 1]; '
            'm->sp--;' % o)


def junklines_im(rng, count=1):
    out = []
    for _ in range(count):
        k = rng.randrange(3)
        if k == 0:
            out.append('    m->jj ^= 0x%016xull;' % rng.getrandbits(64))
        elif k == 1:
            out.append('    m->jj += (uint64_t)m->pc * %dull;'
                       % rng.randrange(2, 97))
        else:
            out.append('    if ((m->pc ^ G_i%d) == 0x%08xu) '
                       '{ m->jj ^= 0x%016xull; }'
                       % (rng.randrange(1, 4), rng.getrandbits(32),
                          rng.getrandbits(64)))
    return '\n'.join(out)


# ---------------------------------------------------------------- ty helpers

TY_C = {'u8': 'uint8_t', 'i8': 'char', 'u16': 'uint16_t', 'i16': 'int16_t',
        'u32': 'uint32_t', 'i32': 'int32_t', 'u64': 'uint64_t',
        'i64': 'int64_t', 'void': 'void'}


def ty_c(ty):
    return TY_C[ty.base] + '*' * ty.ptr


def proto(fn):
    ps = ', '.join('%s %s' % (ty_c(t), n) for t, n in fn.params) or 'void'
    return '%s %s(%s)' % (ty_c(fn.ret), fn.name, ps)


# ---------------------------------------------------------------- main emitter

def emit(ctx, funcs_ir, decoys, tables, user_main_include, opaque_calls=True,
         trace=False):
    """funcs_ir: list of (fn, cipher_bytes). Returns C source string."""
    global TRACE_CALLH
    TRACE_CALLH = ('    if (getenv("LLMVM_TRACE")) fprintf(stderr, '
                   '"callh q=%d na=%d hf=%p\\n", (int)q, (int)na, (void *)hf);'
                   if trace else '')
    rng = ctx.rng
    sch = ctx.sch
    L = []
    A = L.append

    A('''/* auto-generated - do not edit */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

#define NFR %d
#define VSTK %d

typedef struct _vmst {
    const unsigned char *bc; uint32_t pc; uint32_t pp; uint32_t lp;
    uint64_t st[VSTK]; int sp; uint64_t fr[NFR]; int alive;
} vmst;

typedef void (*vmhf)(vmst *);

static uint32_t G_k1, G_k2, G_k3;
static uint32_t G_b1, G_b2, G_b3;   /* base keys: every function's entry state */
static uint64_t G_mk;
static uintptr_t G_t[256];
static uintptr_t G_host[%d];
static unsigned char G_harn[%d];
struct vme { uintptr_t bcp; uint32_t n; unsigned char na; };
static struct vme G_vmt[%d];
static unsigned char *G_db[%d];

static uint32_t rotl(uint32_t v, unsigned r){
    r &= 31u; if (!r) return v; return (v << r) | (v >> (32u - r));
}
static void vm_exec_core(const unsigned char *bc, uint32_t n,
                         unsigned char na, uint64_t *rv);
''' % (NFR, STK, len(ctx.hid_rev), len(ctx.hid_rev),
       len(funcs_ir), max(1, len(ctx.data_slots))))

    # junk functions
    for j in range(4):
        A('''static uint64_t jn%d(void){
    volatile uint64_t q = 0x%016xull;
    q ^= q >> 13; q *= 0x2545F4914F6CDD1Dull; q ^= q >> 27;
    return q;
}''' % (j, rng.getrandbits(64)))

    # decoy tables + functions
    for t in tables:
        A(t)
    A('')
    for d in decoys:
        A(d.code)

    # opaque predicate helper
    A('''static int opq_f(unsigned t){ return (int)(((t * (t + 1u)) & 1u) != 0u); }
''')

    # bytecode arrays + data slot ciphers
    for i, (fn, cipher) in enumerate(funcs_ir):
        A('static const unsigned char BC%d[%d] = {\n%s\n};'
          % (i, len(cipher), cbytes(cipher)))
    for i, blob in enumerate(ctx.data_slots):
        cip = bytes(b ^ sch.dslot8(i, j, ctx.K1, ctx.K2)
                    for j, b in enumerate(blob))
        A('static const unsigned char DS%d[%d] = {\n%s\n};'
          % (i, len(cip), cbytes(cip)))
        A('static unsigned char DB%d[%d];' % (i, len(blob)))

    # ---- V3-c: outer fetch variants ----
    A(kmix_variants(rng, sch, 'km'))
    dmx_fn = rng.choice(('km', 'km2'))
    A('''static unsigned char dmx(unsigned int p){
    return (unsigned char)(%s(0x%08xu ^ (p * 0x%08xu + %uu)) >> %du);
}''' % (dmx_fn, sch.ds, sch.dp, sch.da, sch.dsh))
    NV = rng.randrange(3, 6)
    vnames = []
    for i in range(NV):
        nm = 'nxb%d' % i
        tail = '    s->pc++; s->pp++; s->lp = p;'
        A(fetch_variant(rng, sch, nm, 's->bc', ('G_k1', 'G_k2', 'G_k3'),
                        's->pc', tail, ('km', 'km2')))
        w = 'w%d' % i
        A('static uint32_t %s(vmst *s){'
          'uint32_t r = 0; r |= (uint32_t)%s(s); '
          'r |= (uint32_t)%s(s) << 8; r |= (uint32_t)%s(s) << 16; '
          'r |= (uint32_t)%s(s) << 24; return r; }'
          % (w, nm, nm, nm, nm))
        A('static uint64_t %s_q(vmst *s){'
          'uint64_t r = 0; int i; for (i = 0; i < 8; i++) '
          'r |= (uint64_t)%s(s) << (8 * i); return r; }' % (w, nm))
        vnames.append({'b': nm, 'w32': w, 'w64': '%s_q' % w})

    # ---- V3-a: inner build (draws rng; one program per INNERIZED alias) ----
    ib = InnerBuild(ctx)
    inner_c, inner_byte_name = emit_inner_c(ib, rng, sch)
    A(inner_c)
    for j, byte in enumerate(sorted(ib.programs)):
        cip = ib.programs[byte]
        A('static const unsigned char IM%d[%d] = {\n%s\n};'
          % (j, len(cip), cbytes(cip)))
    im_index = {byte: j for j, byte in enumerate(sorted(ib.programs))}

    # host wrappers
    for hs in ctx.host_specs:
        if hs.name.startswith('jn'):
            for a in hs.arities:
                A('static uint64_t H_%s_%d(uint64_t a0, uint64_t a1, uint64_t a2){'
                  '(void)a0;(void)a1;(void)a2; return jn%s(); }'
                  % (hs.name, a, hs.name[2:]))
            continue
        for a in hs.arities:
            call = {
                'puts': '(uint64_t)puts((const char *)(uintptr_t)a0)',
                'putchar': '(uint64_t)putchar((int)a0)',
                'strlen': '(uint64_t)strlen((const char *)(uintptr_t)a0)',
            }
            if hs.name == 'printf':
                cc = 'printf((const char *)(uintptr_t)a0' + \
                     ''.join(', a%d' % i for i in range(1, a)) + ')'
                cc = '(uint64_t)' + cc
            else:
                cc = call[hs.name]
            unused = ''.join('(void)a%d;' % i for i in range(a, 3))
            A('static uint64_t H_%s_%d(uint64_t a0, uint64_t a1, uint64_t a2){'
              '%s return %s; }' % (hs.name, a, unused, cc))

    # handlers (random opcode order). INNERIZED semantics become trampolines
    # into their inner programs; everything else gets the V3-b shapes.
    used = set()
    helpers = []
    handlers = []
    opcodes = list(range(256))
    rng.shuffle(opcodes)
    for byte in opcodes:
        sem = ctx.opcode_map.get(byte)
        if sem in INNERIZED:
            n = hname(rng, used)
            body = ('static void %s(vmst *s){ (void)s;\n%s\n'
                    '    imx_run(IM%d, s);\n%s\n}'
                    % (n, junklines(rng, rng.randrange(0, 2)),
                       im_index[byte], junklines(rng, rng.randrange(0, 2))))
            handlers.append((byte, n, body))
        else:
            fx = vnames[rng.randrange(NV)]
            n, body = gen_handler(rng, used, sem if sem else 'POISON',
                                  sch=sch, fx=fx, helpers=helpers)
            handlers.append((byte, n, body))
    A('')
    for h in helpers:
        A(h)
    A('')
    for _, _, body in handlers:
        A(body)
    A('')

    # vm_init: keys + dispatch table + host/vm tables + data slots
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
    iv1 = u32(dmap['dec_huff_walk'].value ^ dmap['dec_md5_mix'].value)
    iv2 = u32(dmap['dec_rle_scan'].value + dmap['dec_png_crc'].value)
    iv3 = u32(dmap['dec_bmp_probe'].value ^ dmap['dec_jpeg_idct'].value
              ^ dmap['dec_quant_check'].value)
    ADJI1 = u32(ib.I1 ^ iv1)
    ADJI2 = u32(ib.I2 ^ u32(iv2 * 0x5f1b))
    ADJI3 = u32(ib.I3 - iv3)
    imkb = u32(rotl(ib.I1, 7) + ib.I2)
    ADJIM = u32(ib.IMK ^ imkb)
    A('''static void kload(void){
    uint32_t a = dec_bmp_probe() ^ dec_rle_scan();
    uint32_t b = dec_jpeg_idct() + dec_huff_walk();
    uint32_t c = dec_md5_mix() ^ dec_quant_check() ^ dec_png_crc();
    if (IsDebuggerPresent()) { a ^= 0x35d31fu; b += 7u; }
    G_k1 = rotl(a, 3) ^ 0x%08xu;
    G_k2 = (b * 0x6acdu) ^ 0x%08xu;
    G_k3 = c + 0x%08xu;
    G_b1 = G_k1; G_b2 = G_k2; G_b3 = G_k3;
    G_mk = (uint64_t)(uintptr_t)(rotl(G_k1, 9) + G_k2) ^ 0x%08xull;
    G_i1 = (dec_huff_walk() ^ dec_md5_mix()) ^ 0x%08xu;
    G_i2 = ((dec_rle_scan() + dec_png_crc()) * 0x5f1bu) ^ 0x%08xu;
    G_i3 = (dec_bmp_probe() ^ dec_jpeg_idct() ^ dec_quant_check()) + 0x%08xu;
    G_imk = (uint64_t)(uintptr_t)(rotl(G_i1, 7) + G_i2) ^ 0x%08xull;
}''' % (ADJ1, ADJ2, ADJ3, ADJM, ADJI1, ADJI2, ADJI3, ADJIM))

    A('''
static long g_init;
static void vm_init(void){
    unsigned i, j;
    if (g_init) return;
    g_init = 1;
    kload();''')
    for byte, n, _ in handlers:
        A('    G_t[%d] = (uintptr_t)&%s ^ (uintptr_t)G_mk;' % (byte, n))
    for b in sorted(inner_byte_name):
        A('    G_it[%d] = (uintptr_t)&%s ^ (uintptr_t)G_imk;'
          % (b, inner_byte_name[b]))
    for hid, (name, arity) in sorted(ctx.hid_rev.items()):
        A('    G_host[%d] = (uintptr_t)&H_%s_%d ^ (uintptr_t)G_mk; '
          'G_harn[%d] = %d;' % (hid, name, arity, hid, arity))
    for i, (fn, cipher) in enumerate(funcs_ir):
        A('    G_vmt[%d].bcp = (uintptr_t)&BC%d[0] ^ (uintptr_t)G_mk; '
          'G_vmt[%d].n = %d; G_vmt[%d].na = %d;'
          % (i, i, i, len(cipher), i, len(fn.params)))
    dslot_fn = rng.choice(('km', 'km2'))
    for i, blob in enumerate(ctx.data_slots):
        A('''    { const unsigned char *cc = DS%d; unsigned char *dd = DB%d;
      for (j = 0; j < %d; j++) dd[j] = cc[j] ^ (unsigned char)(%s(G_k1 ^ ((%du * 2654435761u) + j * 7u)) ^ %s(G_k2 + j * 13u + %du));
      G_db[%d] = DB%d; }''' % (i, i, len(blob), dslot_fn, i, dslot_fn, i, i, i))
    A('    (void)i;\n}')

    # core interpreter
    # Every function's layer-0 bytecode is encrypted under the BASE keys, so
    # each invocation resets the current keys to base; the caller's (possibly
    # KSET-rekeyed) state is saved and restored on exit — CALLV nesting and
    # re-entry both stay correct, and the key active at any position remains
    # a static property of that position (loop revisits decrypt identically).
    main_fx = vnames[rng.randrange(NV)]
    A('''
static void vm_exec_core(const unsigned char *bc, uint32_t n,
                         unsigned char na, uint64_t *rv){
    vmst s; unsigned i;
    uint32_t pk1 = G_k1, pk2 = G_k2, pk3 = G_k3;
    G_k1 = G_b1; G_k2 = G_b2; G_k3 = G_b3;
    (void)n;
    s.bc = bc; s.pc = 0; s.pp = 0; s.lp = 0; s.sp = 0; s.alive = 1;
    for (i = 0; i < NFR; i++) s.fr[i] = 0;
    for (i = 0; i < (unsigned)na && i < 3; i++) s.fr[i] = rv[i];
    while (s.alive) {
        unsigned char op = %s(&s);
%s
        ((vmhf)(G_t[op] ^ (uint64_t)G_mk))(&s);
    }
    rv[0] = s.fr[0];
    G_k1 = pk1; G_k2 = pk2; G_k3 = pk3;
}
static void vmx_run(unsigned char fid, uint64_t *rv){
    vm_init();
    vm_exec_core((const unsigned char *)(G_vmt[fid].bcp ^ (uint64_t)G_mk),
                 G_vmt[fid].n, G_vmt[fid].na, rv);
}
''' % (main_fx['b'],
       ('        if (getenv("LLMVM_TRACE")) fprintf(stderr, "pc=%3u op=%3d sp=%d\\n", s.pc, (int)op, s.sp);')
       if trace else ''))

    # wrappers with original signatures (+ opaque decoy calls)
    for i, (fn, _) in enumerate(funcs_ir):
        A('%s;' % proto(fn))
    A('')
    for i, (fn, _) in enumerate(funcs_ir):
        params = ', '.join('%s %s' % (ty_c(t), n) for t, n in fn.params) or 'void'
        args = []
        for t, n in fn.params:
            if t.ptr:
                args.append('(uint64_t)(uintptr_t)%s' % n)
            elif t.base in ('i32', 'i8', 'i16', 'i64'):
                args.append('(uint64_t)(int64_t)%s' % n)
            else:
                args.append('(uint64_t)%s' % n)
        ret = fn.ret
        A('%s %s(%s){' % (ty_c(ret), fn.name, params))
        A('    uint64_t rv[3]; rv[0]=rv[1]=rv[2]=0;')
        for k, e in enumerate(args):
            A('    rv[%d] = %s;' % (k, e))
        if opaque_calls:
            A('    if (opq_f(GetTickCount())) { dec_jpeg_idct(); dec_png_crc(); dec_huff_walk(); }')
        A('    vmx_run(%d, rv);' % i)
        if ret.base == 'void' and ret.ptr == 0:
            A('    (void)rv[0];')
        elif ret.ptr:
            A('    return (%s)(uintptr_t)rv[0];' % ty_c(ret))
        elif ret.base in ('u32', 'u16', 'u8'):
            A('    return (%s)rv[0];' % ty_c(ret))
        elif ret.base in ('i32', 'i8', 'i16', 'i64'):
            A('    return (%s)(int64_t)rv[0];' % ty_c(ret))
        else:
            A('    return rv[0];')
        A('}')

    A('')
    A('#include "%s"' % user_main_include)
    return '\n'.join(L) + '\n'
