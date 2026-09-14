"""VM-in-VM (v3): load-bearing outer handlers re-hosted as inner bytecode.

The v2 blind test (REPORT.md §5) showed the winning attack is semantic lift:
dump every native handler, canonicalize, re-implement the machine in Python.
KSET only blocks *static decryptors* — inside a re-hosted emulator it is just
another opcode. The counter is to make the handler semantics themselves DATA:
the operand-fetch / control-flow / rekey outer ops become programs of a tiny
inner VM whose interpreter is the only native code involved. Until the inner
ISA is lifted, not a single outer byte can even be decoded — and nothing is
incrementally verifiable before both levels are correct.

Layout of an inner program (plain, before encryption):
    [op byte][operand bytes...]... with rel16 branch operands.
The whole byte string is encrypted with the build's INNER Scheme
(enc.Scheme drawn separately from the outer one), keystream keyed by inner
position and the inner keys G_i1..G_i3 — which the outer KSET never touches
(revisit-invariance: an inner program must decode identically no matter when
its outer handler fires).

inner_exec() is the Python mirror of the emitted C interpreter; the fuzz
check in evidence/inner_check.py runs it against reference semantics before
any C is compiled.
"""
from .enc import M32, M64

# ---------------------------------------------------------------- ISA

# micro-ops over (inner value stack v[8], one scratch slot, outer vmst)
INNER_OPS = [
    'IPUSH',      # imm64 (8 bytes LE)
    'IPOP', 'IDUP', 'ISWAP',
    'ISAVE',      # pop -> scratch
    'ILOAD',      # push scratch
    'IADD', 'ISUB', 'IMUL', 'IXOR', 'IAND', 'IOR',
    'ISHL', 'ISHR', 'ISAR',
    'INEG', 'IBNOT', 'INOTL',
    'IMASK32',    # v &= 0xFFFFFFFF
    'ISEXT32',    # sign-extend low 32 bits to 64
    'IROL32',     # imm5 rotate
    'IOS_PUSH',   # inner pop -> outer st[sp++]
    'IOS_POP',    # outer st[--sp] -> inner push
    'IOF_GETD',   # pop q -> push outer fr[q & 63]
    'IOF_SETD',   # pop v, pop q -> outer fr[q & 63] = v
    'IGETDB',     # pop q -> push (u64)G_db[q]
    'IOLDB',      # fetch+decrypt next OUTER stream byte, push it
    'IDXMX',      # pop b -> push b ^ dmx(outer lp)
    'IGETLP',     # push outer lp
    'IPC_GET',    # push outer pc
    'IPC_SET',    # pop -> outer pc = (u32)v
    'ICTEST',     # pop target, pop v; if v: outer pc = (u32)target
    'ICFTEST',    # ... if !v
    'IKEY_GET1', 'IKEY_GET2', 'IKEY_GET3',
    'IKEY_SET1', 'IKEY_SET2', 'IKEY_SET3',
    'IJMP', 'IJT', 'IJF',   # imm16 signed rel
    'IRET',
]

IMM_OPS = {'IPUSH': 8, 'IROL32': 1, 'IJMP': 2, 'IJT': 2, 'IJF': 2}
INNER_SIZES = {op: 1 + IMM_OPS.get(op, 0) for op in INNER_OPS}

STK_MAX = 8


class Prog:
    """Assembly buffer with labels for one inner program."""

    def __init__(self):
        self.code = []      # (op, args...) | ('label', id)
        self.labels = 0

    def emit(self, op, *a):
        self.code.append((op,) + a)

    def label(self):
        self.labels += 1
        return self.labels

    def place(self, lid):
        self.code.append(('label', lid))

    def junk(self, rng, n=None):
        """Dead-but-harmless filler: pushed constants consumed by pops, and a
        never-taken (const-false) skip over realistic filler ops."""
        for _ in range(rng.randrange(1, 4) if n is None else n):
            k = rng.randrange(4)
            if k == 0:
                self.emit('IPUSH', rng.getrandbits(64))
                self.emit('IPOP')
            elif k == 1:
                self.emit('IPUSH', rng.getrandbits(32))
                self.emit('IPUSH', rng.getrandbits(32))
                self.emit('IXOR')
                self.emit('IPOP')
            elif k == 2:
                self.emit('IPUSH', rng.getrandbits(16))
                self.emit('INEG')
                self.emit('IPOP')
            else:
                over = self.label()
                self.emit('IPUSH', rng.randrange(1, 1 << 8))  # nonzero ->
                self.emit('IJT', over)                        # always taken
                for _ in range(rng.randrange(2, 6)):
                    j = rng.randrange(5)
                    if j == 0:
                        self.emit('IPUSH', rng.getrandbits(64))
                    elif j == 1:
                        self.emit('IAND')
                    elif j == 2:
                        self.emit('IOR')
                    elif j == 3:
                        self.emit('ISHL')
                    else:
                        self.emit('IMUL')
                self.place(over)


def _imm(p, v):
    p.emit('IPUSH', v & M64)


def _fetch_le(p, rng, nbytes):
    """Fetch nbytes outer-stream bytes (low -> high), leaving the composed
    little-endian value on the inner stack. The fetch ORDER is fixed by the
    outer stream (b_0 first), so the only exact compositions accumulate in
    order — but the combine varies: shifted bytes live in disjoint bit
    ranges, so IOR == IADD == sum-of-products, bit for bit."""
    combine = rng.choice(('ior', 'iadd', 'imul'))
    _imm(p, 0)
    for i in range(nbytes):
        p.emit('IOLDB')
        if combine == 'imul':
            _imm(p, 256 ** i)
            p.emit('IMUL')
            p.emit('IADD')
        else:
            _imm(p, 8 * i)
            p.emit('ISHL')
            p.emit('IOR' if combine == 'ior' else 'IADD')


def _rel32_target(p, rng):
    """Leave (u32)(pc_after_operand + sext32(rel)) on the inner stack,
    consuming the 4 operand bytes — mirrors the native JMP/JT/JF handlers."""
    _fetch_le(p, rng, 4)
    p.emit('ISEXT32')
    p.emit('IPC_GET')
    p.emit('IADD')
    p.emit('IMASK32')


def program_for(sem, rng, kset_id):
    """Assemble the inner program implementing outer semantic `sem`.
    The outer handler semantics must match gen_c's native templates
    exactly — see evidence/inner_check.py for the differential test."""
    p = Prog()
    p.junk(rng, rng.randrange(0, 2))
    if sem == 'PUSHI':
        _fetch_le(p, rng, 8)
        p.emit('IOS_PUSH')
        p.junk(rng)
        p.emit('IRET')
    elif sem == 'PUSHD':
        p.emit('IOLDB')
        p.emit('IDXMX')
        p.emit('IGETDB')
        p.emit('IOS_PUSH')
        p.junk(rng)
        p.emit('IRET')
    elif sem == 'LDFL':
        p.emit('IOLDB')
        p.emit('IDXMX')
        p.emit('IOF_GETD')
        p.junk(rng)
        p.emit('IOS_PUSH')
        p.emit('IRET')
    elif sem == 'STFL':
        p.emit('IOLDB')
        p.emit('IDXMX')
        p.emit('IOS_POP')
        p.emit('IOF_SETD')
        p.junk(rng)
        p.emit('IRET')
    elif sem == 'JMP':
        _rel32_target(p, rng)
        p.emit('IPC_SET')
        p.junk(rng)
        p.emit('IRET')
    elif sem == 'JT':
        # pop cond first (native order), then fetch+compute the target:
        # ICTEST pops [.., cond, target]
        p.emit('IOS_POP')
        _rel32_target(p, rng)
        p.emit('ICTEST')
        p.junk(rng)
        p.emit('IRET')
    elif sem == 'JF':
        p.emit('IOS_POP')
        _rel32_target(p, rng)
        p.emit('ICFTEST')
        p.junk(rng)
        p.emit('IRET')
    elif sem == 'KSET':
        _kset(p, rng, kset_id)
    else:
        raise KeyError(sem)
    return p


def _kset(p, rng, kset_id):
    """KSET micro-program: pops d from the OUTER stack (the prologue's
    arithmetic leaves it there), exits with the outer stack popped and
    G_k1..3 rekeyed. Formulas mirror enc.Scheme.kset_apply exactly.
    Layout: [d] -> dup, shr32 -> [d, hi] -> ISAVE (scr=hi) -> [d] -> mask32
    -> [lo], hi recovered via ILOAD. u64 inner arithmetic then u32 truncation
    at IKEY_SET* reproduces C's u32-wrapping lanes (only low-32 bits of any
    intermediate affect the stored result)."""
    p.emit('IOS_POP')           # d = outer st[--sp]
    p.emit('IDUP')
    _imm(p, 32)
    p.emit('ISHR')             # [d, hi]
    p.emit('ISAVE')            # scr = hi ; [d]
    p.emit('IMASK32')          # [lo]
    if kset_id == 0:
        # k1' = rotl(k1 ^ lo, 1)
        p.emit('IDUP')         # [lo, lo]
        p.emit('IKEY_GET1')    # [lo, lo, k1]
        p.emit('IXOR')         # [lo, k1^lo]
        p.emit('IROL32', 1)    # [lo, k1']  (k1' on top)
        p.emit('IKEY_SET1')    # [lo]
        # k2' = k2 + hi + lo*0x9E3779B9
        p.emit('IDUP')         # [lo, lo]
        _imm(p, 0x9E3779B9)
        p.emit('IMUL')         # [lo, lo*C]
        p.emit('ILOAD')        # [lo, lo*C, hi]
        p.emit('IADD')         # [lo, lo*C+hi]
        p.emit('IKEY_GET2')
        p.emit('IADD')         # [lo, k2']
        p.emit('IKEY_SET2')    # [lo]
        # k3' = k3 ^ rotl(lo + hi, 5)
        p.emit('ILOAD')        # [lo, hi]
        p.emit('IADD')         # [lo+hi]
        p.emit('IROL32', 5)
        p.emit('IKEY_GET3')
        p.emit('IXOR')
        p.emit('IKEY_SET3')
    elif kset_id == 1:
        # k1' = k1 + lo
        p.emit('IDUP')
        p.emit('IKEY_GET1')
        p.emit('IADD')
        p.emit('IKEY_SET1')    # [lo]
        # k2' = rotl(k2 ^ hi, 3)
        p.emit('ILOAD')        # [lo, hi]
        p.emit('IKEY_GET2')
        p.emit('IXOR')
        p.emit('IROL32', 3)
        p.emit('IKEY_SET2')    # [lo]
        # k3' = (k3 ^ hi*0x85EBCA6B) + lo
        p.emit('ILOAD')        # [lo, hi]
        _imm(p, 0x85EBCA6B)
        p.emit('IMUL')
        p.emit('IKEY_GET3')
        p.emit('IXOR')
        p.emit('IADD')
        p.emit('IKEY_SET3')
    else:
        # k1' = k1 ^ lo*0x27220A95
        p.emit('IDUP')
        _imm(p, 0x27220A95)
        p.emit('IMUL')
        p.emit('IKEY_GET1')
        p.emit('IXOR')
        p.emit('IKEY_SET1')    # [lo]
        # k2' = k2 - hi   (ISUB is a-b with b on top: push k2 first)
        p.emit('IKEY_GET2')    # [lo, k2]
        p.emit('ILOAD')        # [lo, k2, hi]
        p.emit('ISUB')         # [lo, k2 - hi]
        p.emit('IKEY_SET2')    # [lo]
        # k3' = rotl(k3 + lo, 7) ^ hi
        p.emit('IDUP')
        p.emit('IKEY_GET3')
        p.emit('IADD')
        p.emit('IROL32', 7)
        p.emit('ILOAD')
        p.emit('IXOR')
        p.emit('IKEY_SET3')
    p.junk(rng)
    p.emit('IRET')


# ---------------------------------------------------------------- linearize

def linearize(prog, imap, rng):
    """prog -> plain bytes. imap: {sem: [opcode bytes]} (random per build).
    Jump offsets are rel16 from the end of the operand."""
    off = []
    labels_at = {}
    cur = 0
    for ins in prog.code:
        if ins[0] == 'label':
            labels_at[ins[1]] = cur
            continue
        off.append((cur, ins))
        cur += INNER_SIZES[ins[0]]
    plain = bytearray(cur)
    for at, ins in off:
        op, args = ins[0], ins[1:]
        plain[at] = rng.choice(imap[op])
        if op == 'IPUSH':
            v = args[0] & M64
            for i in range(8):
                plain[at + 1 + i] = (v >> (8 * i)) & 0xFF
        elif op == 'IROL32':
            plain[at + 1] = args[0] & 31
        elif op in ('IJMP', 'IJT', 'IJF'):
            rel = labels_at[args[0]] - (at + 3)
            assert -32768 <= rel < 32768, 'inner rel16 overflow'
            r = rel & 0xFFFF
            plain[at + 1] = r & 0xFF
            plain[at + 2] = r >> 8
    return bytes(plain)


def draw_imap(rng):
    """Random inner opcode assignment: 1-2 aliases per semantic, rest poison."""
    pool = list(range(256))
    rng.shuffle(pool)
    imap = {}
    for op in INNER_OPS:
        n = 2 if rng.random() < 0.4 else 1
        mine = pool[:n]
        del pool[:n]
        imap[op] = mine
    return imap


def imopmap(imap):
    """Inverse map: opcode byte -> semantic (poison slots absent)."""
    m = {}
    for sem, ops in imap.items():
        for b in ops:
            m[b] = sem
    return m


# ---------------------------------------------------------------- mirror VM

class Outer:
    """Minimal model of the outer state the inner VM touches."""

    def __init__(self, bc=None, k1=0, k2=0, k3=0, dmx_fn=None, ks8_fn=None,
                 db=None, nfr=64):
        self.bc = bc or b''
        self.pc = 0
        self.pp = 0
        self.lp = 0
        self.st = []
        self.fr = [0] * nfr
        self.k1, self.k2, self.k3 = k1, k2, k3
        self.dmx_fn = dmx_fn or (lambda p: 0)
        self.ks8_fn = ks8_fn or (lambda p, a, b, c: 0)
        self.db = db or []


def inner_exec(plain, opmap, outer, max_steps=100000):
    """Python mirror of the emitted C inner interpreter.
    opmap: {opcode byte: semantic}. Returns steps executed."""
    v = []
    scr = 0
    pc = 0
    steps = 0
    while pc < len(plain) and steps < max_steps:
        steps += 1
        op = plain[pc]
        sem = opmap[op]
        pc += 1
        if sem == 'IPUSH':
            v.append(int.from_bytes(plain[pc:pc + 8], 'little'))
            pc += 8
        elif sem == 'IROL32':
            r = plain[pc] & 31
            pc += 1
            x = v.pop() & M32
            v.append(((x << r) | (x >> (32 - r))) & M32 if r else x)
        elif sem in ('IJMP', 'IJT', 'IJF'):
            rel = int.from_bytes(plain[pc:pc + 2], 'little', signed=True)
            pc += 2
            if sem == 'IJMP':
                pc += rel
            elif sem == 'IJT':
                if v.pop():
                    pc += rel
            else:
                if not v.pop():
                    pc += rel
        elif sem == 'IPOP':
            v.pop()
        elif sem == 'IDUP':
            v.append(v[-1])
        elif sem == 'ISWAP':
            v[-1], v[-2] = v[-2], v[-1]
        elif sem == 'ISAVE':
            scr = v.pop()
        elif sem == 'ILOAD':
            v.append(scr)
        elif sem in ('IADD', 'ISUB', 'IMUL', 'IXOR', 'IAND', 'IOR',
                     'ISHL', 'ISHR', 'ISAR'):
            b = v.pop()
            a = v.pop()
            if sem == 'IADD':
                r = (a + b) & M64
            elif sem == 'ISUB':
                r = (a - b) & M64
            elif sem == 'IMUL':
                r = (a * b) & M64
            elif sem == 'IXOR':
                r = a ^ b
            elif sem == 'IAND':
                r = a & b
            elif sem == 'IOR':
                r = a | b
            elif sem == 'ISHL':
                r = (a << (b & 63)) & M64
            elif sem == 'ISHR':
                r = a >> (b & 63)
            else:  # ISAR: arithmetic shift of the signed reinterpretation
                sa = a - (1 << 64) if a >= (1 << 63) else a
                r = (sa >> (b & 63)) & M64
            v.append(r)
        elif sem == 'INEG':
            v.append((-v.pop()) & M64)
        elif sem == 'IBNOT':
            v.append(v.pop() ^ M64)
        elif sem == 'INOTL':
            v.append(1 if v.pop() == 0 else 0)
        elif sem == 'IMASK32':
            v.append(v.pop() & M32)
        elif sem == 'ISEXT32':
            x = v.pop() & M32
            v.append(x | 0xFFFFFFFF00000000 if x & 0x80000000 else x)
        elif sem == 'IOS_PUSH':
            outer.st.append(v.pop())
        elif sem == 'IOS_POP':
            v.append(outer.st.pop())
        elif sem == 'IOF_GETD':
            q = v.pop()
            v.append(outer.fr[q & 63])
        elif sem == 'IOF_SETD':
            val = v.pop()
            q = v.pop()
            outer.fr[q & 63] = val
        elif sem == 'IGETDB':
            q = v.pop()
            v.append(outer.db[q])
        elif sem == 'IOLDB':
            p = outer.pc
            b = outer.bc[p] ^ outer.ks8_fn(p, outer.k1, outer.k2, outer.k3)
            outer.pc = p + 1
            outer.pp += 1
            outer.lp = p
            v.append(b)
        elif sem == 'IDXMX':
            b = v.pop()
            v.append(b ^ outer.dmx_fn(outer.lp))
        elif sem == 'IGETLP':
            v.append(outer.lp)
        elif sem == 'IPC_GET':
            v.append(outer.pc)
        elif sem == 'IPC_SET':
            outer.pc = v.pop() & M32
        elif sem == 'ICTEST':
            t = v.pop() & M32
            cond = v.pop()
            if cond:
                outer.pc = t
        elif sem == 'ICFTEST':
            t = v.pop() & M32
            cond = v.pop()
            if not cond:
                outer.pc = t
        elif sem == 'IKEY_GET1':
            v.append(outer.k1)
        elif sem == 'IKEY_GET2':
            v.append(outer.k2)
        elif sem == 'IKEY_GET3':
            v.append(outer.k3)
        elif sem == 'IKEY_SET1':
            outer.k1 = v.pop() & M32
        elif sem == 'IKEY_SET2':
            outer.k2 = v.pop() & M32
        elif sem == 'IKEY_SET3':
            outer.k3 = v.pop() & M32
        elif sem == 'IRET':
            return steps
        else:
            raise KeyError(sem)
        assert len(v) <= STK_MAX, 'inner stack overflow'
    return steps
