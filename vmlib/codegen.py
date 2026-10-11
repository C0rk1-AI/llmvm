"""Subset-C -> VM IR -> encrypted bytecode.

Frame layout: fr[0..nparams-1] params (fr[0] doubles as return value),
then locals, scratch = top 4 of NFR (never allocated).
All values u64 in slots; widths only matter for memory access.
"""
from . import enc
from .enc import M64
from .lang import Ty, UNSIGNED_BASES, StructDef
from struct import pack as _spack

NFR = 64          # frame slots (power of 2)
SCRATCH = [60, 61, 62, 63]
STK = 256
LOCMAX = 512      # per-invocation frame-local aggregate storage (vmst.loc)

# semantic ops without operands
PLAIN_OPS = [
    'ADD', 'SUB', 'MUL', 'DIVU', 'DIVS', 'MODU', 'MODS',
    'AND', 'OR', 'XOR', 'SHL', 'SHR', 'SAR',
    'NEG', 'NOTL', 'BNOT',
    'EQU', 'NEQ', 'LTS', 'LEQS', 'GTS', 'GEQS',
    'LTU', 'LEQU', 'GTU', 'GEQU',
    'DUP', 'POP', 'SWAP',
    'LD8', 'LD16', 'LD32', 'LD64', 'ST8', 'ST16', 'ST32', 'ST64',
    'TRU8', 'TRU16', 'TRU32',
    'RET', 'NOP',
]
ALL_OPS = PLAIN_OPS + ['PUSHI', 'PUSHD', 'LDFL', 'STFL', 'CALLH', 'CALLV',
                       'JMP', 'JT', 'JF', 'KSET']

# feature-gated semantic ops: aliases are drawn ONLY when the build actually
# uses the feature, so legacy sources keep the exact rng draw sequence (and
# evidence/fold_true_key.py keeps replaying byte-identical builds).
FLOAT_OPS = [
    'FADD', 'FSUB', 'FMUL', 'FDIV',             # f64 arithmetic
    'FADDS', 'FSUBS', 'FMULS', 'FDIVS',         # f32 arithmetic (per-op rounding)
    'I2FD', 'U2FD', 'FD2I', 'FD2U',             # int64 <-> f64
    'F2D', 'D2F',                               # f32 <-> f64 (bit-exact widen/narrow)
    'FEQ', 'FLT', 'FLE',                        # f64 compare (ordered; NaN -> 0)
]
EXT_OPS = {'float': FLOAT_OPS, 'narray': ['LAA'], 'struct': ['LAA'],
           'varargs': ['VNEXT']}

SIZES = {'PUSHI': 9, 'PUSHD': 2, 'LDFL': 2, 'STFL': 2, 'CALLH': 2, 'CALLV': 2,
         'JMP': 5, 'JT': 5, 'JF': 5, 'LAA': 3}


def loadop(size):
    return {1: 'LD8', 2: 'LD16', 4: 'LD32', 8: 'LD64'}[size]


def stopop(size):
    return {1: 'ST8', 2: 'ST16', 4: 'ST32', 8: 'ST64'}[size]


class HostSpec:
    def __init__(self, name, arities, sigs=None, ret='u'):
        self.name = name
        self.arities = list(arities)   # e.g. [2] or [1,2,3]
        # sigs[i]: per-arity argument kinds, one char per arg:
        #   'u' unsigned/whatever (bits pass through), 'i' signed integer,
        #   'p' pointer, 'd' double (u64 slot carries IEEE754 f64 bits)
        # None entry = untyped legacy host (printf-style; call-site types rule)
        self.sigs = list(sigs) if sigs else [None] * len(self.arities)
        self.ret = ret                 # return kind: 'u' bits, 'd' f64 bits


class VMFuncInfo:
    def __init__(self, fn, fid):
        self.fn = fn
        self.fid = fid
        self.bytecode = None   # filled after linearize


class Ctx:
    """Shared build context: rng, host/data tables, opcode aliases, keys."""

    def __init__(self, rng, funcs, hosts, data, data_types,
                 features=(), structs=None):
        # hosts: {name: {'arity':n} or {'arities':[..]},
        #         optional 'sig': per-arity arg-kind string(s), 'ret': kind}
        # data: {name: bytes}; data_types: {name: (base, ptr)}
        # features: {'float','struct','narray','varargs'} subset actually used
        # structs: {tag: lang.StructDef} from parse_full (member layout)
        self.rng = rng
        # per-build keystream/rekey parameter set (drawn FIRST so the whole
        # build is conditioned on it)
        self.sch = enc.Scheme(rng)
        self.funcs = funcs
        self.features = set(features or ())
        self.structs = structs or {}
        self.host_specs = []
        self.host_by_name = {}
        for name, spec in hosts.items():
            ar = spec.get('arities') or [spec['arity']]
            sig = spec.get('sig')
            if isinstance(sig, str):
                sigs = [sig]
            elif sig:
                sigs = list(sig)
            else:
                sigs = None
            if sigs is not None and len(sigs) != len(ar):
                raise RuntimeError(f'host {name}: sig count != arities')
            hs = HostSpec(name, ar, sigs, spec.get('ret', 'u'))
            self.host_specs.append(hs)
            self.host_by_name[name] = hs
        # junk hosts (arity 0) used by dead code
        for j in range(4):
            hs = HostSpec(f'jn{j}', [0])
            self.host_specs.append(hs)
        self.hid = {}  # (name, arity) -> hid
        self.hid_rev = {}  # hid -> (name, arity)
        for hs in self.host_specs:
            for a in hs.arities:
                hid = len(self.hid_rev)
                self.hid[(hs.name, a)] = hid
                self.hid_rev[hid] = (hs.name, a)

        self.data = dict(data)
        self.data_types = {k: Ty(*v) for k, v in data_types.items()}
        self.str_slots = {}
        self.data_slots = []      # list of bytes payloads (manifest data + strings)
        self.slot_ids = {}        # name -> slot
        for name, blob in self.data.items():
            self.slot_ids[name] = len(self.data_slots)
            self.data_slots.append(bytes(blob))

        self.vm_info = {}
        for i, fn in enumerate(funcs):
            self.vm_info[fn.name] = VMFuncInfo(fn, i)

        # opcode aliases: semantic op -> [opcode bytes]
        pool = list(range(256))
        rng.shuffle(pool)
        self.opcode_map = {}   # opcode byte -> semantic
        self.aliases = {}
        for op in ALL_OPS:
            n = 3 if op in ('ADD', 'XOR', 'LDFL', 'STFL', 'PUSHI') else (
                2 if rng.random() < 0.5 else 1)
            mine = pool[:n]
            del pool[:n]
            self.aliases[op] = mine
            for b in mine:
                self.opcode_map[b] = op

        # feature-gated op aliases: appended after the legacy loop, and only
        # for features the source actually uses — builds that stay in the
        # legacy subset keep the exact rng draw sequence (replay identity).
        ext = []
        for feat in ('float', 'narray', 'struct', 'varargs'):
            if feat in self.features:
                for op in EXT_OPS[feat]:
                    if op not in ext:
                        ext.append(op)
        for op in ext:
            n = 2 if rng.random() < 0.5 else 1
            mine = pool[:n]
            del pool[:n]
            self.aliases[op] = mine
            for b in mine:
                self.opcode_map[b] = op

        self.K1 = rng.getrandbits(32)
        self.K2 = rng.getrandbits(32)
        self.K3 = rng.getrandbits(32)
        self.MK = rng.getrandbits(32) | 0x10000
        self.dead_rate = 0.22

    def pick(self, op):
        return self.rng.choice(self.aliases[op])

    def slot_for_string(self, s):
        if s in self.str_slots:
            return self.str_slots[s]
        blob = s.encode('latin-1', 'replace') + b'\0'
        sid = len(self.data_slots)
        self.data_slots.append(blob)
        self.str_slots[s] = sid
        return sid


def num_ty(v):
    """C type of an integer literal by value range (int -> unsigned -> long)."""
    v &= 0xFFFFFFFFFFFFFFFF
    if v <= 0x7FFFFFFF:
        return Ty('i32')
    if v <= 0xFFFFFFFF:
        return Ty('u32')
    if v <= 0x7FFFFFFFFFFFFFFF:
        return Ty('i64')
    return Ty('u64')


def iprod(dims):
    r = 1
    for d in dims or ():
        r *= d
    return r


def f64_bits(v):
    return int.from_bytes(_spack('<d', float(v)), 'little')


def f32_bits(v):
    return int.from_bytes(_spack('<f', float(v)), 'little')


class FnGen:
    def __init__(self, fn, ctx):
        self.fn = fn
        self.ctx = ctx
        self.code = []            # list of (op, args...) / ('label', id)
        self.labels = 0
        self.scopes = [{}]
        self.nslots = 0
        self.locbytes = 0         # bytes allocated in vmst.loc so far
        self.loops = []           # (continue_label, break_label)

    # ---------- helpers ----------
    def emit(self, op, *a):
        self.code.append((op,) + a)

    def sex(self, ty):
        """Sign-extend a narrow signed value in-place on the stack.
        Slots hold zero-extended values; signed ops need the sign replicated:
        sex_s(v) = (v << (64-8s)) SAR (64-8s)  -- the top bit of the width
        must land in bit 63 before the arithmetic shift replicates it."""
        if ty is None or ty.is_ptr() or ty.is_unsigned() or ty.is_float():
            return
        s = ty.size()
        if s < 8:
            k = 64 - s * 8
            self.emit('PUSHI', k)
            self.emit('SHL')
            self.emit('PUSHI', k)
            self.emit('SAR')

    def trunc(self, ty):
        """Emit truncation per C semantics for a sub-u64 integer type."""
        if ty is None or ty.is_ptr() or ty.is_float():
            return
        s = ty.size()
        if s == 1:
            self.emit('TRU8')
        elif s == 2:
            self.emit('TRU16')
        elif s == 4:
            self.emit('TRU32')

    def to_f(self, ty, wide):
        """Convert the value of type ty on the stack to the working float
        precision (f64 if wide else f32). Slots carry IEEE754 bits; f32 is a
        zero-extended 32-bit pattern."""
        if ty.is_float():
            if wide and ty.base == 'f32':
                self.emit('F2D')
            elif not wide and ty.base == 'f64':
                self.emit('D2F')
            return
        if ty.is_ptr():
            raise RuntimeError(f'{self.fn.name}: pointer in float context')
        if ty.size() < 8 and not ty.is_unsigned():
            self.sex(ty)              # narrow signed -> i64 value first
        self.emit('U2FD' if ty.is_unsigned() else 'I2FD')
        if not wide:
            self.emit('D2F')

    def to_f64(self, ty):
        self.to_f(ty, True)

    def convert(self, st, dt):
        """Value of scalar type st on the stack -> representation of dt.
        Pointers and same-class ints keep the legacy bit conventions."""
        if st is None or dt is None:
            return
        if st.is_ptr() or dt.is_ptr():
            return                    # pointer <-> int: bits pass through
        sf, df = st.is_float(), dt.is_float()
        if sf and df:
            if st.base == 'f32' and dt.base == 'f64':
                self.emit('F2D')
            elif st.base == 'f64' and dt.base == 'f32':
                self.emit('D2F')
            return
        if sf and not df:
            if st.base == 'f32':
                self.emit('F2D')  # f32 slots carry the zero-extended 32-bit
                # pattern; widen to real f64 bits before the f64 conversion
            self.emit('FD2U' if dt.is_unsigned() else 'FD2I')
            if dt.size() < 8:
                self.trunc(dt)
            return
        if not sf and df:
            if st.size() < 8 and not st.is_unsigned():
                self.sex(st)
            self.emit('U2FD' if st.is_unsigned() else 'I2FD')
            if dt.base == 'f32':
                self.emit('D2F')
            return
        if dt.size() < 8:
            self.trunc(dt)            # int -> int: legacy semantics

    def gen_cond(self, e):
        """Condition value on the stack. Floats compare against +0.0 so that
        -0.0 is falsy (a raw bits-nonzero test would get it wrong)."""
        t = self.type_of(e)
        self.gen_expr(e)
        if t.is_float():
            self.to_f64(t)
            self.emit('PUSHI', 0)     # +0.0
            self.emit('FEQ')          # == 0.0
            self.emit('NOTL')         # != 0.0

    def newlabel(self):
        self.labels += 1
        return self.labels

    def place(self, lid):
        self.code.append(('label', lid))

    def lookup(self, name):
        for sc in reversed(self.scopes):
            if name in sc:
                return sc[name]
        if name in self.ctx.slot_ids:
            return ('data', self.ctx.slot_ids[name], self.ctx.data_types.get(
                name, Ty('i8', 1)))
        return None

    def decl_slot(self, name, ty):
        slot = self.nslots
        if slot >= SCRATCH[0]:
            raise RuntimeError(f'{self.fn.name}: too many locals (>60)')
        self.nslots += 1
        self.scopes[-1][name] = ('var', slot, ty)
        return slot

    def alloc_loc(self, size, align):
        """Allocate frame-local aggregate storage (vmst.loc)."""
        off = (self.locbytes + align - 1) // align * align
        if off + size > LOCMAX:
            raise RuntimeError(f'{self.fn.name}: frame locals exceed '
                               f'{LOCMAX} bytes')
        self.locbytes = off + size
        return off

    def decay_ty(self, ty, dims):
        """C array decay: array-of-T -> pointer-to-first-element. Multi-dim
        arrays keep the remaining dims (adims/stride) so each indexing peels
        exactly one level; a struct object yields a pointer to itself."""
        p = ty.clone(ptr=ty.ptr + 1)
        if dims is not None and len(dims) > 1:
            p.adims = tuple(dims[1:])
            p.stride = ty.size() * iprod(dims[1:])
        return p

    def elem_ty(self, bt):
        """Type of one dereference of pointer bt (scalar / struct / pointer)."""
        if bt.ptr > 1:
            return bt.clone(ptr=bt.ptr - 1)
        return Ty(bt.base, 0, bt.sname, bt.sdef)

    def peel_ty(self, bt):
        """Pure half of peel_one: the expression type after indexing or
        dereferencing bt once (no code emitted)."""
        if bt.adims is not None:
            rest = bt.adims[1:]
            p = Ty(bt.base, bt.ptr, bt.sname, bt.sdef)
            if rest:
                p.adims = rest
                esz = self.elem_ty(bt).size()
                p.stride = esz * iprod(rest)
            return p
        return self.elem_ty(bt)

    def peel_one(self, bt):
        """Emitting half: the element address of bt is on the stack. Loads
        the scalar/pointer VALUE; keeps the address for arrays (decay) and
        struct objects (address is the value). Returns the expression ty."""
        t = self.peel_ty(bt)
        if bt.adims is not None:
            return t                     # array peel: address stands as ptr
        if bt.ptr > 1:
            self.emit(loadop(8))
            return t
        if t.base == 'struct':
            return t.clone(ptr=1)        # struct object: address is the value
        self.emit(loadop(t.size()))
        return t

    def obj_ty(self, e):
        """Object view of an expression: (ty, dims) with arrays keeping
        their dims (no decay) — used for member-of-array-element etc."""
        if e[0] == 'var':
            r = self.lookup(e[1])
            if r is None:
                raise RuntimeError(f'{self.fn.name}: undefined {e[1]}')
            if r[0] == 'larr':
                return r[2], r[3]
            return r[2], None
        if e[0] == 'index':
            return self.peel_ty(self.type_of(e[1])), None
        if e[0] == 'member':
            fty, fdims, _off = self.member_field(e)
            return fty, fdims
        if e[0] == 'deref':
            return self.peel_ty(self.type_of(e[1])), None
        return self.type_of(e), None

    def member_field(self, e):
        """Pure: ('member', base, name, deref) -> (field_ty, field_dims, offset)."""
        base, fname, deref = e[1], e[2], e[3]
        if deref:
            pt = self.type_of(base)
            if pt.ptr != 1 or pt.base != 'struct' or pt.sdef is None:
                raise RuntimeError(f'{self.fn.name}: -> on non-struct-pointer')
            sd = pt.sdef
        else:
            bty, bdims = self.obj_ty(base)
            if bty.base != 'struct' or bty.sdef is None:
                raise RuntimeError(f'{self.fn.name}: . on non-struct')
            if bdims is not None:
                raise RuntimeError(f'{self.fn.name}: . on whole array')
            sd = bty.sdef
        return sd.field(fname)

    # ---------- entry ----------
    def generate(self):
        if self.fn.ret.base == 'struct' and self.fn.ret.ptr == 0:
            raise RuntimeError(f'{self.fn.name}: returning structs by value '
                               f'is not supported (use a pointer)')
        for ty, name in self.fn.params:
            if ty.base == 'struct' and ty.ptr == 0:
                raise RuntimeError(f'{self.fn.name}: struct param {name!r} '
                                   f'must be passed by pointer')
            self.decl_slot(name, ty)
        self.gen_stmt(self.fn.body)
        self.emit('RET')
        return self

    # ---------- statements ----------
    def gen_stmt(self, s):
        k = s[0]
        if k == 'block':
            self.scopes.append({})
            for st in s[1]:
                self.gen_stmt(st)
                self.maybe_dead()
            self.scopes.pop()
        elif k == 'decl':
            ty, name, init = s[1], s[2], s[3]
            dims = s[4] if len(s) > 4 else None
            if dims is not None or (ty.base == 'struct' and ty.ptr == 0):
                # array / struct object: allocate in frame-local storage
                if init is not None:
                    raise RuntimeError(f'{self.fn.name}: initializer not '
                                       f'supported for array/struct {name!r}')
                cnt = iprod(dims) if dims is not None else 1
                size = ty.size() * cnt
                if size <= 0:
                    raise RuntimeError(f'{self.fn.name}: bad size for {name!r}')
                off = self.alloc_loc(size, StructDef.align_of(ty))
                self.scopes[-1][name] = ('larr', off, ty, dims)
            else:
                slot = self.decl_slot(name, ty)
                if init is not None:
                    vt = self.type_of(init)
                    if ty.is_float() and not vt.is_float() and not vt.is_ptr():
                        # int expr -> float var: reduce to the C-promoted
                        # width first (chained sub-32-bit arithmetic keeps
                        # u64 slots; (double)u64 of it would read 2^64-ish)
                        self.convert(self.gen_fsrc(init), ty)
                    else:
                        self.gen_expr(init)
                        if vt.is_float() or ty.is_float():
                            self.convert(vt, ty)
                        else:
                            self.trunc(ty)
                    self.emit('STFL', slot)
        elif k == 'multidecl':
            for d in s[1]:
                self.gen_stmt(d)
        elif k == 'expr':
            self.gen_expr(s[1])
            self.emit('POP')
        elif k == 'if':
            _, c, th, el = s
            lelse, lend = self.newlabel(), self.newlabel()
            self.gen_cond(c)
            self.emit('JF', lelse)
            self.gen_stmt(th)
            self.emit('JMP', lend)
            self.place(lelse)
            if el is not None:
                self.gen_stmt(el)
            self.place(lend)
        elif k == 'while':
            _, c, b = s
            lcond, lend = self.newlabel(), self.newlabel()
            self.place(lcond)
            self.gen_cond(c)
            self.emit('JF', lend)
            self.loops.append((lcond, lend))
            self.gen_stmt(b)
            self.loops.pop()
            self.emit('JMP', lcond)
            self.place(lend)
        elif k == 'for':
            _, init, cond, step, body = s
            lcond, lcont, lend = self.newlabel(), self.newlabel(), self.newlabel()
            if init is not None:
                self.gen_stmt(init)
            self.place(lcond)
            if cond is not None:
                self.gen_cond(cond)
                self.emit('JF', lend)
            self.loops.append((lcont, lend))
            self.gen_stmt(body)
            self.loops.pop()
            self.place(lcont)
            if step is not None:
                self.gen_stmt(('expr', step))
            self.emit('JMP', lcond)
            self.place(lend)
        elif k == 'return':
            if s[1] is not None:
                vt = self.type_of(s[1])
                if (self.fn.ret.is_float() and not vt.is_float()
                        and not vt.is_ptr()):
                    self.convert(self.gen_fsrc(s[1]), self.fn.ret)
                else:
                    self.gen_expr(s[1])
                    if vt.is_float() or self.fn.ret.is_float():
                        self.convert(vt, self.fn.ret)
                    else:
                        self.trunc(self.fn.ret)   # convert to the declared type
                self.emit('STFL', 0)
            self.emit('RET')
        elif k == 'break':
            self.emit('JMP', self.loops[-1][1])
        elif k == 'continue':
            self.emit('JMP', self.loops[-1][0])
        elif k == 'empty':
            pass
        else:
            raise RuntimeError(f'unknown stmt {k}')

    def maybe_dead(self):
        rng = self.ctx.rng
        if rng.random() > self.ctx.dead_rate:
            return
        sc = rng.choice(SCRATCH)
        # ~30% of dead insertions are never-executed junk BLOCKS: an
        # always-taken skip over a run of realistic ops (fake CALLV/LD/ST,
        # fake immediates). Bloats scripted pattern-matching with plausible
        # but bogus control/data flow.
        kind = 3 if rng.random() < 0.30 else rng.randrange(3)
        if kind == 0:
            self.emit('LDFL', sc)
            self.emit('PUSHI', rng.getrandbits(64))
            self.emit('XOR')
            self.emit('STFL', sc)
        elif kind == 1:
            self.emit('CALLH', self.ctx.hid[(f'jn{rng.randrange(4)}', 0)])
            self.emit('POP')
        elif kind == 2:
            self.emit('PUSHI', rng.getrandbits(64))
            self.emit('POP')
        else:
            over = self.newlabel()
            inner = self.newlabel()
            if rng.random() < 0.5:
                self.emit('PUSHI', rng.randrange(1, 1 << 8))
                self.emit('JT', over)
            else:
                self.emit('PUSHI', 0)
                self.emit('JF', over)
            for _ in range(rng.randrange(3, 9)):
                k = rng.randrange(6)
                if k == 0:
                    self.emit('PUSHI', rng.getrandbits(64))
                elif k == 1:
                    self.emit('CALLV', rng.randrange(len(self.ctx.vm_info)))
                elif k == 2:
                    self.emit('LDFL', sc)
                elif k == 3:
                    self.emit('STFL', sc)
                elif k == 4:
                    self.emit(rng.choice(('ADD', 'XOR', 'MUL', 'SHL')))
                else:
                    self.emit('LD64')
            self.emit('JMP', inner)
            self.place(inner)
            self.place(over)

    # ---------- expressions ----------
    def gen_expr(self, e):
        """Leaves exactly one value on the stack; returns Ty."""
        k = e[0]
        if k == 'num':
            self.emit('PUSHI', e[1] & 0xFFFFFFFFFFFFFFFF)
            return num_ty(e[1])
        if k == 'fnum':
            val, is32 = e[1], e[2]
            self.emit('PUSHI', f32_bits(val) if is32 else f64_bits(val))
            return Ty('f32' if is32 else 'f64')
        if k == 'str':
            sid = self.ctx.slot_for_string(e[1])
            self.emit('PUSHD', sid)
            return Ty('i8', 1)
        if k == 'var':
            r = self.lookup(e[1])
            if r is None:
                raise RuntimeError(f'{self.fn.name}: undefined {e[1]}')
            if r[0] == 'data':
                self.emit('PUSHD', r[1])
                return r[2]
            if r[0] == 'larr':
                self.emit('LAA', r[1])
                return self.decay_ty(r[2], r[3])
            self.emit('LDFL', r[1])
            return r[2]
        if k == 'bin':
            if e[1] in ('&&', '||'):
                return self.gen_bool(e)
            return self.gen_bin(e)
        if k == 'un':
            return self.gen_un(e)
        if k == 'cast':
            ty, sub = e[1], e[2]
            st = self.type_of(sub)
            if (ty.ptr == 0 and st.ptr == 0 and ty.is_float()
                    and not st.is_float() and not st.is_ptr()):
                # (float)(int chain): reduce to the C-promoted width first
                self.convert(self.gen_fsrc(sub), ty)
                return ty
            self.gen_expr(sub)
            if ty.ptr == 0 and st.ptr == 0 and (st.is_float() or ty.is_float()):
                self.convert(st, ty)   # int <-> float / float <-> float
                return ty
            if ty.ptr == 0 and not st.is_ptr():
                ss, ts = st.size(), ty.size()
                if ss < ts and not st.is_unsigned():
                    self.sex(st)      # widening a signed value sign-extends
                if ts < 8:
                    self.trunc(ty)    # narrowing truncates low bits
            return ty
        if k == 'index':
            base, idx = e[1], e[2]
            bt = self.gen_expr(base)
            if not bt.is_ptr():
                raise RuntimeError('index on non-pointer')
            self.gen_expr(idx)
            sz = bt.esize()
            self.emit('PUSHI', sz)
            self.emit('MUL')
            self.emit('ADD')
            return self.peel_one(bt)
        if k == 'deref':
            pt = self.gen_expr(e[1])
            if not pt.is_ptr():
                raise RuntimeError('deref on non-pointer')
            return self.peel_one(pt)
        if k == 'member':
            w, fty, agg, fdims = self.gen_lval_addr(e)
            if agg:
                if fdims is not None:
                    return self.decay_ty(fty, fdims)  # array field decays
                return fty.clone(ptr=1)               # nested struct: address
            self.emit(loadop(w))
            return fty
        if k == 'call':
            return self.gen_call(e)
        if k == 'assign':
            return self.gen_assign(e[1], e[2])
        if k == 'assignop':
            return self.gen_assignop(e[1], e[2], e[3])
        if k == 'varfn':
            raise RuntimeError('function reference outside call')
        raise RuntimeError(f'unknown expr {k}')

    def c_type(self, e):
        """Width-faithful C type of e (usual arithmetic conversions applied
        at every chain node). type_of collapses chained int arithmetic to
        Ty('u64') — congruent for stores, but (double)u64 of a wrapped value
        would read the wrong magnitude, so float boundaries use this."""
        if e[0] == 'bin' and e[1] in ('<<', '>>'):
            lt = self.c_type(e[2])
            return Ty('u64') if lt.is_ptr() else lt
        if e[0] == 'bin' and e[1] not in ('&&', '||'):
            lt, rt = self.c_type(e[2]), self.c_type(e[3])
            if lt.is_ptr() or rt.is_ptr():
                return Ty('u64')
            if lt.is_float() or rt.is_float():
                return self.type_of(e)      # float result types are exact
            if lt.size() == 8 or rt.size() == 8:
                return lt if lt.size() == 8 else rt
            return Ty('u32' if lt.is_unsigned() or rt.is_unsigned()
                      else 'i32')
        if e[0] == 'un' and e[1] in ('-', '~'):
            return self.c_type(e[2])       # result keeps the operand type
        return self.type_of(e)

    def gen_fsrc(self, e):
        """Emit an int expression entering float context, reduced to its
        C-promoted width first (see c_type). Returns the reduced type."""
        ct = self.c_type(e)
        self.gen_expr(e)
        if ct.size() < 8:
            if ct.is_unsigned():
                self.trunc(ct)
            else:
                self.sex(ct)               # narrow signed -> true i64 value
        return ct

    def gen_fload(self, e, t, wide):
        """Operand of float arithmetic/compare: floats load as-is, ints go
        through the width-reducing path."""
        if t.is_float():
            self.gen_expr(e)
        else:
            t = self.gen_fsrc(e)
        self.to_f(t, wide)

    def type_of(self, e):
        """Type of an expression without emitting code (mirrors gen_expr)."""
        k = e[0]
        if k == 'num':
            return num_ty(e[1])
        if k == 'fnum':
            return Ty('f32' if e[2] else 'f64')
        if k == 'str':
            return Ty('i8', 1)
        if k == 'var':
            r = self.lookup(e[1])
            if r is None:
                raise RuntimeError(f'{self.fn.name}: undefined {e[1]}')
            if r[0] == 'larr':
                return self.decay_ty(r[2], r[3])
            return r[2]
        if k == 'bin':
            op = e[1]
            if op in ('&&', '||'):
                return Ty('i32')
            lt = self.type_of(e[2])
            rt = self.type_of(e[3])
            if lt.is_float() or rt.is_float():
                if op in ('==', '!=', '<', '>', '<=', '>='):
                    return Ty('i32')
                if op in ('+', '-', '*', '/'):
                    wide = ((lt.is_float() and lt.base == 'f64') or
                            (rt.is_float() and rt.base == 'f64'))
                    return Ty('f64' if wide else 'f32')
                raise RuntimeError(f'{self.fn.name}: {op} on float')
            if op in ('+', '-'):
                if lt.is_ptr() and not rt.is_ptr():
                    return lt
                if rt.is_ptr() and not lt.is_ptr():
                    return rt
                return Ty('u64')
            if op in ('==', '!=', '<', '>', '<=', '>='):
                return Ty('i32')
            if op in ('<<', '>>'):
                return Ty('u64') if lt.is_ptr() else lt
            return Ty('u64')
        if k == 'un':
            if e[1] == '-':
                return self.type_of(e[2])
            if e[1] == '!':
                return Ty('i32')
            return Ty('u64')     # ~
        if k == 'cast':
            return e[1]
        if k == 'index':
            return self.peel_ty(self.type_of(e[1]))
        if k == 'deref':
            return self.peel_ty(self.type_of(e[1]))
        if k == 'member':
            fty, fdims, _off = self.member_field(e)
            if fdims is not None:
                return self.decay_ty(fty, fdims)
            if fty.base == 'struct' and fty.ptr == 0:
                return fty.clone(ptr=1)
            return fty
        if k == 'call':
            name = e[1][1]
            if name in self.ctx.vm_info:
                return self.ctx.vm_info[name].fn.ret
            if name == 'vv_next':
                return Ty('u64')
            hs = self.ctx.host_by_name.get(name)
            if hs is not None and hs.ret == 'd':
                return Ty('f64')
            return Ty('u64')
        if k == 'assign':
            return self.lval_type(e[1])
        if k == 'assignop':
            return self.lval_type(e[2])
        return Ty('u64')

    def lval_type(self, lv):
        if lv[0] == 'var':
            r = self.lookup(lv[1])
            return r[2] if r else Ty('u64')
        if lv[0] == 'deref':
            return self.peel_ty(self.type_of(lv[1]))
        if lv[0] == 'index':
            return self.peel_ty(self.type_of(lv[1]))
        if lv[0] == 'member':
            fty, _dims, _off = self.member_field(lv)
            if fty.base == 'struct' and fty.ptr == 0:
                return fty.clone(ptr=1)
            return fty
        return Ty('u64')

    def gen_bin(self, e):
        _, op, le, re_ = e
        lt = self.type_of(le)
        rt = self.type_of(re_)
        if lt.is_float() or rt.is_float():
            if lt.is_ptr() or rt.is_ptr():
                raise RuntimeError(f'{self.fn.name}: pointer/float arithmetic')
            return self.gen_fbin(op, le, re_, lt, rt)
        # sign-extension plan: slots hold zero-extended values; signed ops on
        # narrow operands need the sign replicated first.
        uns = lt.is_unsigned() or rt.is_unsigned()
        sex_l = sex_r = False
        if op in ('+', '-', '*'):
            # narrow signed operands must be sign-extended before arithmetic
            sex_l = lt.size() < 8 and not lt.is_ptr() and not lt.is_unsigned()
            sex_r = rt.size() < 8 and not rt.is_ptr() and not rt.is_unsigned()
        elif op == '>>' and not lt.is_unsigned():
            sex_l = lt.size() < 8
        elif op in ('/', '%', '<', '>', '<=', '>=') and not uns:
            sex_l = lt.size() < 8 and not lt.is_ptr()
            sex_r = rt.size() < 8 and not rt.is_ptr()
        lt2 = self.gen_expr(le)
        if sex_l:
            self.sex(lt)
        rt2 = self.gen_expr(re_)
        if sex_r:
            self.sex(rt)
        if op == '&&':
            raise RuntimeError('&& handled at top level')
        if op in ('+', '-'):
            # pointer scaling
            if lt.is_ptr() and not rt.is_ptr():
                self.emit('PUSHI', lt.esize())
                self.emit('MUL')
            elif rt.is_ptr() and not lt.is_ptr():
                self.emit('SWAP')
                self.emit('PUSHI', rt.esize())
                self.emit('MUL')
                self.emit('SWAP')
            self.emit('ADD' if op == '+' else 'SUB')
            if lt.is_ptr():
                return lt
            if rt.is_ptr():
                return rt
            if max(lt.size(), rt.size()) <= 4:
                self.trunc(Ty('u32'))   # C: sub-int64 arithmetic wraps at 32
            return Ty('u64')
        if op in ('==', '!='):
            self.emit('EQU' if op == '==' else 'NEQ')
            return Ty('i32')
        if op in ('<', '>', '<=', '>='):
            uns = lt.is_unsigned() or rt.is_unsigned()
            m = {'<': ('LTU', 'LTS'), '>': ('GTU', 'GTS'),
                 '<=': ('LEQU', 'LEQS'), '>=': ('GEQU', 'GEQS')}
            a, b = m[op]
            self.emit(a if uns else b)
            return Ty('i32')
        if op in ('<<', '>>'):
            if op == '<<':
                self.emit('SHL')
            else:
                self.emit('SHR' if lt.is_unsigned() else 'SAR')
            if not lt.is_ptr() and lt.size() <= 4:
                self.trunc(Ty('u32'))
            return Ty('u64') if lt.is_ptr() else lt
        if op in ('&', '|', '^'):
            self.emit({'&': 'AND', '|': 'OR', '^': 'XOR'}[op])
            if not lt.is_ptr() and not rt.is_ptr() and max(lt.size(), rt.size()) <= 4:
                self.trunc(Ty('u32'))
            return Ty('u64')
        if op in ('*', '/', '%'):
            uns = lt.is_unsigned() or rt.is_unsigned()
            if op == '*':
                self.emit('MUL')
            elif op == '/':
                self.emit('DIVU' if uns else 'DIVS')
            else:
                self.emit('MODU' if uns else 'MODS')
            if not lt.is_ptr() and not rt.is_ptr() and max(lt.size(), rt.size()) <= 4:
                self.trunc(Ty('u32'))
            return Ty('u64')
        if op in ('&&', '||'):
            pass
        raise RuntimeError(f'binop {op} unsupported')

    def gen_fbin(self, op, le, re_, lt, rt):
        """Float arithmetic / compare. f32 ops round per-op (FLT_EVAL_METHOD
        0, matching MSVC SSE); compares run in f64 (widening f32 is exact)."""
        if op in ('&', '|', '^', '<<', '>>', '%'):
            raise RuntimeError(f'{self.fn.name}: {op} on float')
        if op in ('==', '!=', '<', '>', '<=', '>='):
            self.gen_fload(le, lt, True)
            self.gen_fload(re_, rt, True)
            m = {'==': 'FEQ', '!=': 'FEQ', '<': 'FLT', '<=': 'FLE',
                 '>': 'FLT', '>=': 'FLE'}
            if op in ('>', '>='):
                self.emit('SWAP')     # a>b  ==  b<a
            self.emit(m[op])
            if op == '!=':
                self.emit('NOTL')
            return Ty('i32')
        if op not in ('+', '-', '*', '/'):
            raise RuntimeError(f'binop {op} on float')
        wide = ((lt.is_float() and lt.base == 'f64') or
                (rt.is_float() and rt.base == 'f64'))
        self.gen_fload(le, lt, wide)
        self.gen_fload(re_, rt, wide)
        fop = ({'+': 'FADD', '-': 'FSUB', '*': 'FMUL', '/': 'FDIV'} if wide
               else {'+': 'FADDS', '-': 'FSUBS', '*': 'FMULS', '/': 'FDIVS'})
        self.emit(fop[op])
        return Ty('f64' if wide else 'f32')

    def gen_bool(self, e):
        """short-circuit && / || wrapper"""
        op = e[1]
        ltrue, lfalse, lend = self.newlabel(), self.newlabel(), self.newlabel()
        self.gen_bool_operand(e[2])
        if op == '&&':
            self.emit('JF', lfalse)
            self.gen_bool_operand(e[3])
            self.emit('JF', lfalse)
            self.emit('PUSHI', 1)
            self.emit('JMP', lend)
            self.place(lfalse)
            self.emit('PUSHI', 0)
            self.place(lend)
        else:
            self.emit('JT', ltrue)
            self.gen_bool_operand(e[3])
            self.emit('JT', ltrue)
            self.emit('PUSHI', 0)
            self.emit('JMP', lend)
            self.place(ltrue)
            self.emit('PUSHI', 1)
            self.place(lend)
        return Ty('i32')

    def gen_bool_operand(self, e):
        """Operand of &&/||: floats normalize to int truth (-0.0 falsy)."""
        t = self.type_of(e)
        if t.is_float():
            self.gen_cond(e)
        else:
            self.gen_expr_nosc(e)

    def gen_expr_nosc(self, e):
        if e[0] == 'bin' and e[1] in ('&&', '||'):
            return self.gen_bool(e)
        return self.gen_expr(e)

    def gen_un(self, e):
        _, op, sub = e
        if op == '-':
            t = self.type_of(sub)
            if t.is_float():
                self.gen_expr(sub)
                self.emit('PUSHI', 0x8000000000000000 if t.base == 'f64'
                          else 0x80000000)
                self.emit('XOR')          # flip the sign bit (NaN-safe)
                return t
            self.emit('PUSHI', 0)
            self.gen_expr(sub)
            self.emit('SUB')
            if not t.is_ptr() and t.size() <= 4:
                self.trunc(Ty('u32'))
            return t
        if op == '!':
            t = self.type_of(sub)
            if t.is_float():
                self.gen_expr(sub)
                self.to_f64(t)
                self.emit('PUSHI', 0)
                self.emit('FEQ')
                return Ty('i32')
            self.gen_expr(sub)
            self.emit('NOTL')
            return Ty('i32')
        if op == '~':
            t = self.type_of(sub)
            if t.is_float():
                raise RuntimeError(f'{self.fn.name}: ~ on float')
            self.gen_expr(sub)
            self.emit('BNOT')
            if not t.is_ptr() and t.size() <= 4:
                self.trunc(Ty('u32'))
            return Ty('u64')
        raise RuntimeError(f'unop {op}')

    def gen_call(self, e):
        _, callee, args = e
        if callee[0] != 'varfn':
            raise RuntimeError('only direct calls supported')
        name = callee[1]
        arity = len(args)
        if name == 'vv_start':
            if not self.fn.variadic:
                raise RuntimeError(f'{self.fn.name}: vv_start outside a '
                                   f'variadic function')
            if arity:
                raise RuntimeError('vv_start takes no args')
            # varargs are pre-staged by CALLV / the wrapper; emit a marker
            # value so the statement-expression stack discipline holds
            self.emit('PUSHI', 0)
            return Ty('u64')
        if name == 'vv_next':
            if not self.fn.variadic:
                raise RuntimeError(f'{self.fn.name}: vv_next outside a '
                                   f'variadic function')
            if arity:
                raise RuntimeError('vv_next takes no args')
            self.emit('VNEXT')
            return Ty('u64')
        if name in self.ctx.vm_info:
            info = self.ctx.vm_info[name]
            nfix = len(info.fn.params)
            if info.fn.variadic:
                if arity < nfix:
                    raise RuntimeError(f'{name}: arity mismatch')
                # varargs are pushed FIRST (with C default promotions), then
                # the fixed params — the CALLV handler pops the fixed params
                # into rr and stages the varargs for the callee in order.
                for a in args[nfix:]:
                    ct = self.c_type(a)     # width-faithful for chains too
                    self.gen_expr(a)
                    if ct.is_float():
                        if ct.base == 'f32':
                            self.emit('F2D')   # float -> double promotion
                    elif ct.size() < 8 and not ct.is_unsigned():
                        self.sex(ct)           # narrow signed -> i64 value
                for a, (_pt, _pn) in zip(args[:nfix], info.fn.params):
                    vt = self.type_of(a)
                    if _pt.is_float() and not vt.is_float() and not vt.is_ptr():
                        self.convert(self.gen_fsrc(a), _pt)
                        continue
                    self.gen_expr(a)
                    if vt.is_float() or _pt.is_float():
                        self.convert(vt, _pt)
                    else:
                        self.trunc(_pt)
                self.emit('CALLV', info.fid)
                return info.fn.ret
            if arity != nfix:
                raise RuntimeError(f'{name}: arity mismatch')
            for a, (_pt, _pn) in zip(args, info.fn.params):
                vt = self.type_of(a)
                if _pt.is_float() and not vt.is_float() and not vt.is_ptr():
                    self.convert(self.gen_fsrc(a), _pt)
                    continue
                self.gen_expr(a)
                if vt.is_float() or _pt.is_float():
                    self.convert(vt, _pt)
                else:
                    self.trunc(_pt)
            self.emit('CALLV', info.fid)
            return info.fn.ret
        key = (name, arity)
        if key in self.ctx.hid:
            hs = self.ctx.host_by_name[name]
            sig = hs.sigs[hs.arities.index(arity)] if hs.sigs else None
            for i, a in enumerate(args):
                at = self.type_of(a)
                kind = sig[i] if sig else None
                if kind == 'd' and not at.is_float() and not at.is_ptr():
                    # 'd' host param fed an int expr: C-promoted width first
                    self.convert(self.gen_fsrc(a), Ty('f64'))
                    continue
                self.gen_expr(a)
                if at.is_float():
                    # untyped hosts & 'd' params: default promotion to double
                    if at.base == 'f32':
                        self.emit('F2D')
                elif kind == 'd':
                    self.convert(at, Ty('f64'))
            self.emit('CALLH', self.ctx.hid[key])
            if hs.ret == 'd':
                return Ty('f64')
            return Ty('u64')
        raise RuntimeError(f'{self.fn.name}: unknown callee {name}/{arity}')

    # lvalue address (for deref/index/member targets): pushes the address;
    # returns (width, ty, is_aggregate, dims). is_aggregate marks
    # array/struct objects (assignment through them is rejected); dims is
    # non-None only for whole-array member fields.
    def gen_lval_addr(self, lv):
        if lv[0] == 'deref':
            pt = self.gen_expr(lv[1])
            if not pt.is_ptr():
                raise RuntimeError('deref on non-pointer')
            et = self.elem_ty(pt)
            agg = pt.adims is not None or (et.base == 'struct'
                                            and et.ptr == 0)
            return et.size(), et, agg, None
        if lv[0] == 'index':
            base, idx = lv[1], lv[2]
            bt = self.gen_expr(base)
            if not bt.is_ptr():
                raise RuntimeError('index on non-pointer')
            self.gen_expr(idx)
            self.emit('PUSHI', bt.esize())
            self.emit('MUL')
            self.emit('ADD')
            et = self.elem_ty(bt)
            agg = bt.adims is not None or (et.base == 'struct'
                                           and et.ptr == 0)
            return et.size(), et, agg, None
        if lv[0] == 'var':
            r = self.lookup(lv[1])
            if r is not None and r[0] == 'larr':
                self.emit('LAA', r[1])
                return r[2].size(), r[2], True, r[3]
            raise RuntimeError('bad lvalue ' + lv[1])
        if lv[0] == 'member':
            base, deref = lv[1], lv[3]
            if deref:
                self.gen_expr(base)          # pointer value
            else:
                self.gen_lval_addr(base)     # object address (may be agg)
            fty, fdims, foff = self.member_field(lv)
            if foff:
                self.emit('PUSHI', foff)
                self.emit('ADD')
            agg = fdims is not None or (fty.base == 'struct' and fty.ptr == 0)
            return fty.size(), fty, agg, fdims
        raise RuntimeError('bad lvalue')

    def gen_assign(self, lv, rv):
        if lv[0] == 'var':
            r = self.lookup(lv[1])
            if r is None or r[0] != 'var':
                raise RuntimeError(f'cannot assign {lv[1]}')
            vt = self.type_of(rv)
            if r[2].is_float() and not vt.is_float() and not vt.is_ptr():
                # int expr -> float var: C-promoted width first
                self.convert(self.gen_fsrc(rv), r[2])
            else:
                self.gen_expr(rv)
                if vt.is_float() or r[2].is_float():
                    self.convert(vt, r[2])   # assignment converts to var type
                else:
                    self.trunc(r[2])
            self.emit('DUP')
            self.emit('STFL', r[1])
            return r[2]
        sz, elty, agg, _dims = self.gen_lval_addr(lv)
        if agg:
            raise RuntimeError('assignment to array/struct aggregate '
                               'is not supported')
        vt = self.type_of(rv)
        if elty.is_float() and not vt.is_float() and not vt.is_ptr():
            self.convert(self.gen_fsrc(rv), elty)
        else:
            self.gen_expr(rv)
            if vt.is_float() or elty.is_float():
                self.convert(vt, elty)
        self.emit(stopop(sz))
        # re-load as expression value
        self.gen_lval_addr(lv)
        self.emit(loadop(sz))
        return elty

    def gen_assignop(self, binop, lv, rv):
        if lv[0] == 'var':
            r = self.lookup(lv[1])
            if r is None or r[0] != 'var':
                raise RuntimeError(f'cannot assign {lv[1]}')
            rty = r[2]
            vt = self.type_of(rv)
            if rty.is_float() or vt.is_float():
                return self.gen_fassignop(binop, None, r[1], rty, vt, rv)
            self.emit('LDFL', r[1])
            if (binop in ('+', '-', '*', '/', '%', '>>') and not rty.is_ptr()
                    and not rty.is_unsigned() and rty.size() < 8):
                self.sex(rty)
            self.gen_expr(rv)
            if (binop in ('+', '-', '*', '/', '%') and not vt.is_ptr()
                    and not vt.is_unsigned() and vt.size() < 8):
                self.sex(vt)
            self.emit(self.binop_ir(binop, rty))
            if not rty.is_ptr() and rty.size() < 8:
                self.trunc(rty)       # compound assign wraps at the var type
            self.emit('DUP')
            self.emit('STFL', r[1])
            return rty
        sz, elty, agg, _dims = self.gen_lval_addr(lv)
        if agg:
            raise RuntimeError('compound assign on array/struct aggregate')
        vt = self.type_of(rv)
        if elty.is_float() or vt.is_float():
            return self.gen_fassignop(binop, (lv, sz), None, elty, vt, rv)
        self.emit('DUP')
        self.emit(loadop(sz))
        self.gen_expr(rv)
        self.emit(self.binop_ir(binop, elty))
        self.emit(stopop(sz))
        self.gen_lval_addr(lv)
        self.emit(loadop(sz))
        return elty

    def gen_fassignop(self, binop, lval, slot, rty, vt, rv):
        """Compound float assign: x op= rhs. lval=None -> frame slot path;
        otherwise lval=(lv, sz) -> memory path (address pushed by caller)."""
        if binop not in ('+', '-', '*', '/'):
            raise RuntimeError(f'{self.fn.name}: float assignop {binop}')
        wide = rty.base == 'f64'
        fop = ({'+': 'FADD', '-': 'FSUB', '*': 'FMUL', '/': 'FDIV'} if wide
               else {'+': 'FADDS', '-': 'FSUBS', '*': 'FMULS', '/': 'FDIVS'})
        if lval is None:
            self.emit('LDFL', slot)
            self.to_f(rty, wide)
            self.gen_fload(rv, vt, wide)
            self.emit(fop[binop])
            self.emit('DUP')
            self.emit('STFL', slot)
            return rty
        lv, sz = lval
        self.emit('DUP')
        self.emit(loadop(sz))
        self.to_f(rty, wide)
        self.gen_fload(rv, vt, wide)
        self.emit(fop[binop])
        self.emit(stopop(sz))
        self.gen_lval_addr(lv)
        self.emit(loadop(sz))
        return rty

    def binop_ir(self, op, ty):
        if op in ('+', '-', '*', '&', '|', '^', '<<'):
            return {'+': 'ADD', '-': 'SUB', '*': 'MUL', '&': 'AND',
                    '|': 'OR', '^': 'XOR', '<<': 'SHL'}[op]
        if op == '>>':
            return 'SHR' if ty.is_unsigned() else 'SAR'
        if op in ('/', '%'):
            uns = ty.is_unsigned()
            return ('DIVU' if uns else 'DIVS') if op == '/' else (
                'MODU' if uns else 'MODS')
        raise RuntimeError(f'assignop {op}')


def linearize(gen, ctx):
    """IR -> plaintext bytes (with precompensated operands), returns bytes."""
    off = []
    labels_at = {}
    cur = 0
    for ins in gen.code:
        if ins[0] == 'label':
            labels_at[ins[1]] = cur
            continue
        off.append((cur, ins))
        cur += SIZES.get(ins[0], 1)
    total = cur

    plain = bytearray(total)
    for at, ins in off:
        op, args = ins[0], ins[1:]
        p = at
        plain[p] = ctx.pick(op)
        if op == 'PUSHI':
            v = args[0] & 0xFFFFFFFFFFFFFFFF
            for i in range(8):
                plain[p + 1 + i] = (v >> (8 * i)) & 0xFF
        elif op in ('PUSHD', 'LDFL', 'STFL', 'CALLH', 'CALLV'):
            v = args[0] & 0xFF
            q = p + 1
            plain[q] = v ^ ctx.sch.dmx8(q)
        elif op == 'LAA':
            v = args[0] & 0xFFFF       # plain LE imm16 (like PUSHI's imm64)
            plain[p + 1] = v & 0xFF
            plain[p + 2] = (v >> 8) & 0xFF
        elif op in ('JMP', 'JT', 'JF'):
            target = labels_at[args[0]]
            rel = target - (p + 5)
            r = rel & 0xFFFFFFFF
            for i in range(4):
                plain[p + 1 + i] = (r >> (8 * i)) & 0xFF
    return bytes(plain), labels_at


def gen_prologue(ctx):
    """1-3 straight-line KSET layers for a function entry.

    Each layer computes a random u64 delta via real VM arithmetic on PUSHI
    immediates, then KSET pops it and rekeys the keystream. Anti-script
    rationale: the base keys are NOT enough to decrypt past the first KSET —
    a decryptor must parse the decrypted instruction stream (variable-length
    opcodes), evaluate the prologue arithmetic, and replicate the per-build
    rekey scheme, once per function. Revisit-safe: the prologue sits before
    every label, so it runs exactly once per invocation, in order — the key
    active at position p stays a static property of p.
    Returns (ir_instructions, deltas)."""
    rng = ctx.rng
    ir, deltas = [], []
    for _ in range(rng.randrange(1, 4)):
        form = rng.randrange(4)
        if form == 0:
            a, b, c = (rng.getrandbits(64) for _ in range(3))
            ir += [('PUSHI', a), ('PUSHI', b), ('XOR',),
                   ('PUSHI', c), ('ADD',)]
            deltas.append(((a ^ b) + c) & M64)
        elif form == 1:
            a, b = rng.getrandbits(64), rng.getrandbits(64)
            ir += [('PUSHI', a), ('PUSHI', b), ('MUL',)]
            deltas.append((a * b) & M64)
        elif form == 2:
            a, b, d = (rng.getrandbits(64) for _ in range(3))
            ir += [('PUSHI', a), ('PUSHI', b), ('SUB',),
                   ('PUSHI', d), ('XOR',)]
            deltas.append(((a - b) & M64) ^ d)
        else:
            a, b, c, e = (rng.getrandbits(64) for _ in range(4))
            ir += [('PUSHI', a), ('PUSHI', b), ('AND',), ('PUSHI', c),
                   ('XOR',), ('PUSHI', e), ('ADD',)]
            deltas.append((((a & b) ^ c) + e) & M64)
        ir.append(('KSET',))
    return ir, deltas


def encrypt(plain, gen, deltas, ctx):
    """Segment-wise XOR: keys rekey right after each KSET opcode byte
    (the byte itself is fetched under the outgoing keys)."""
    sch = ctx.sch
    k1, k2, k3 = ctx.K1, ctx.K2, ctx.K3
    out = bytearray(len(plain))
    off = 0
    di = 0
    for ins in gen.code:
        if ins[0] == 'label':
            continue
        size = SIZES.get(ins[0], 1)
        for q in range(off, off + size):
            out[q] = plain[q] ^ sch.ks8(q, k1, k2, k3)
        if ins[0] == 'KSET':
            k1, k2, k3 = sch.kset_apply(k1, k2, k3, deltas[di])
            di += 1
        off += size
    assert off == len(plain), 'size walk mismatch'
    assert di == len(deltas), 'KSET/delta count mismatch'
    return bytes(out)


def build_function(fn, ctx):
    """Full per-function pipeline: IR (+dead code) -> KSET prologue prepend
    -> linearize -> segment-aware encrypt. Returns (gen, cipher, deltas)."""
    gen = FnGen(fn, ctx).generate()
    pro, deltas = gen_prologue(ctx)
    gen.code = pro + gen.code
    plain, _ = linearize(gen, ctx)
    cipher = encrypt(plain, gen, deltas, ctx)
    return gen, cipher, deltas


def gen_function(fn, ctx):
    return FnGen(fn, ctx).generate()
