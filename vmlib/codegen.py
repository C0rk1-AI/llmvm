"""Subset-C -> VM IR -> encrypted bytecode.

Frame layout: fr[0..nparams-1] params (fr[0] doubles as return value),
then locals, scratch = top 4 of NFR (never allocated).
All values u64 in slots; widths only matter for memory access.
"""
from . import enc
from .enc import M64
from .lang import Ty, UNSIGNED_BASES

NFR = 64          # frame slots (power of 2)
SCRATCH = [60, 61, 62, 63]
STK = 256

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

SIZES = {'PUSHI': 9, 'PUSHD': 2, 'LDFL': 2, 'STFL': 2, 'CALLH': 2, 'CALLV': 2,
         'JMP': 5, 'JT': 5, 'JF': 5}


def loadop(size):
    return {1: 'LD8', 2: 'LD16', 4: 'LD32', 8: 'LD64'}[size]


def stopop(size):
    return {1: 'ST8', 2: 'ST16', 4: 'ST32', 8: 'ST64'}[size]


class HostSpec:
    def __init__(self, name, arities):
        self.name = name
        self.arities = list(arities)   # e.g. [2] or [1,2,3]


class VMFuncInfo:
    def __init__(self, fn, fid):
        self.fn = fn
        self.fid = fid
        self.bytecode = None   # filled after linearize


class Ctx:
    """Shared build context: rng, host/data tables, opcode aliases, keys."""

    def __init__(self, rng, funcs, hosts, data, data_types):
        # hosts: {name: {'arity':n} or {'arities':[..]}}
        # data: {name: bytes}; data_types: {name: (base, ptr)}
        self.rng = rng
        # per-build keystream/rekey parameter set (drawn FIRST so the whole
        # build is conditioned on it)
        self.sch = enc.Scheme(rng)
        self.funcs = funcs
        self.host_specs = []
        self.host_by_name = {}
        for name, spec in hosts.items():
            ar = spec.get('arities') or [spec['arity']]
            hs = HostSpec(name, ar)
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


class FnGen:
    def __init__(self, fn, ctx):
        self.fn = fn
        self.ctx = ctx
        self.code = []            # list of (op, args...) / ('label', id)
        self.labels = 0
        self.scopes = [{}]
        self.nslots = 0
        self.loops = []           # (continue_label, break_label)

    # ---------- helpers ----------
    def emit(self, op, *a):
        self.code.append((op,) + a)

    def trunc(self, ty):
        """Emit truncation per C semantics for a sub-u64 integer type."""
        if ty is None or ty.is_ptr():
            return
        s = ty.size()
        if s == 1:
            self.emit('TRU8')
        elif s == 2:
            self.emit('TRU16')
        elif s == 4:
            self.emit('TRU32')

    def sex(self, ty):
        """Sign-extend a narrow signed value in-place on the stack.
        Slots hold zero-extended values; signed ops need the sign replicated:
        sex_s(v) = (v << (64-8s)) SAR (64-8s)  -- the top bit of the width
        must land in bit 63 before the arithmetic shift replicates it."""
        if ty is None or ty.is_ptr() or ty.is_unsigned():
            return
        s = ty.size()
        if s < 8:
            k = 64 - s * 8
            self.emit('PUSHI', k)
            self.emit('SHL')
            self.emit('PUSHI', k)
            self.emit('SAR')

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

    # ---------- entry ----------
    def generate(self):
        for ty, name in self.fn.params:
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
            _, ty, name, init = s
            slot = self.decl_slot(name, ty)
            if init is not None:
                self.gen_expr(init)
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
            self.gen_expr(c)
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
            self.gen_expr(c)
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
                self.gen_expr(cond)
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
                self.gen_expr(s[1])
                self.trunc(self.fn.ret)   # convert to the declared return type
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
            self.gen_expr(sub)
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
            it = self.gen_expr(idx)
            sz = bt.esize()
            self.emit('PUSHI', sz)
            self.emit('MUL')
            self.emit('ADD')
            self.emit(loadop(sz))
            return Ty(bt.base, 0)
        if k == 'deref':
            pt = self.gen_expr(e[1])
            if not pt.is_ptr():
                raise RuntimeError('deref on non-pointer')
            self.emit(loadop(pt.esize()))
            return Ty(pt.base, 0)
        if k == 'call':
            return self.gen_call(e)
        if k == 'assign':
            return self.gen_assign(e[1], e[2])
        if k == 'assignop':
            return self.gen_assignop(e[1], e[2], e[3])
        if k == 'varfn':
            raise RuntimeError('function reference outside call')
        raise RuntimeError(f'unknown expr {k}')

    def type_of(self, e):
        """Type of an expression without emitting code (mirrors gen_expr)."""
        k = e[0]
        if k == 'num':
            return num_ty(e[1])
        if k == 'str':
            return Ty('i8', 1)
        if k == 'var':
            r = self.lookup(e[1])
            if r is None:
                raise RuntimeError(f'{self.fn.name}: undefined {e[1]}')
            return r[2]
        if k == 'bin':
            op = e[1]
            if op in ('&&', '||'):
                return Ty('i32')
            lt = self.type_of(e[2])
            rt = self.type_of(e[3])
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
            return Ty(self.type_of(e[1]).base, 0)
        if k == 'deref':
            return Ty(self.type_of(e[1]).base, 0)
        if k == 'call':
            name = e[1][1]
            if name in self.ctx.vm_info:
                return self.ctx.vm_info[name].fn.ret
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
            return Ty(self.type_of(lv[1]).base, 0)
        if lv[0] == 'index':
            return Ty(self.type_of(lv[1]).base, 0)
        return Ty('u64')

    def gen_bin(self, e):
        _, op, le, re_ = e
        lt = self.type_of(le)
        rt = self.type_of(re_)
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

    def gen_bool(self, e):
        """short-circuit && / || wrapper"""
        op = e[1]
        ltrue, lfalse, lend = self.newlabel(), self.newlabel(), self.newlabel()
        self.gen_expr_nosc(e[2])
        if op == '&&':
            self.emit('JF', lfalse)
            self.gen_expr_nosc(e[3])
            self.emit('JF', lfalse)
            self.emit('PUSHI', 1)
            self.emit('JMP', lend)
            self.place(lfalse)
            self.emit('PUSHI', 0)
            self.place(lend)
        else:
            self.emit('JT', ltrue)
            self.gen_expr_nosc(e[3])
            self.emit('JT', ltrue)
            self.emit('PUSHI', 0)
            self.emit('JMP', lend)
            self.place(ltrue)
            self.emit('PUSHI', 1)
            self.place(lend)
        return Ty('i32')

    def gen_expr_nosc(self, e):
        if e[0] == 'bin' and e[1] in ('&&', '||'):
            return self.gen_bool(e)
        return self.gen_expr(e)

    def gen_un(self, e):
        _, op, sub = e
        if op == '-':
            t = self.type_of(sub)
            self.emit('PUSHI', 0)
            self.gen_expr(sub)
            self.emit('SUB')
            if not t.is_ptr() and t.size() <= 4:
                self.trunc(Ty('u32'))
            return t
        if op == '!':
            self.gen_expr(sub)
            self.emit('NOTL')
            return Ty('i32')
        if op == '~':
            t = self.type_of(sub)
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
        if name in self.ctx.vm_info:
            info = self.ctx.vm_info[name]
            if arity != len(info.fn.params):
                raise RuntimeError(f'{name}: arity mismatch')
            for a, (_pt, _pn) in zip(args, info.fn.params):
                self.gen_expr(a)
                self.trunc(_pt)       # convert to the callee's param type
            self.emit('CALLV', info.fid)
            return info.fn.ret
        key = (name, arity)
        if key in self.ctx.hid:
            for a in args:
                self.gen_expr(a)
            self.emit('CALLH', self.ctx.hid[key])
            return Ty('u64')
        raise RuntimeError(f'{self.fn.name}: unknown callee {name}/{arity}')

    # lvalue address (for deref/index targets): pushes address, returns width & elem ty
    def gen_lval_addr(self, lv):
        if lv[0] == 'deref':
            pt = self.gen_expr(lv[1])
            return pt.esize(), Ty(pt.base, 0)
        if lv[0] == 'index':
            base, idx = lv[1], lv[2]
            bt = self.gen_expr(base)
            self.gen_expr(idx)
            self.emit('PUSHI', bt.esize())
            self.emit('MUL')
            self.emit('ADD')
            return bt.esize(), Ty(bt.base, 0)
        raise RuntimeError('bad lvalue')

    def gen_assign(self, lv, rv):
        if lv[0] == 'var':
            r = self.lookup(lv[1])
            if r is None or r[0] != 'var':
                raise RuntimeError(f'cannot assign {lv[1]}')
            self.gen_expr(rv)
            self.trunc(r[2])          # assignment converts to the var type
            self.emit('DUP')
            self.emit('STFL', r[1])
            return r[2]
        sz, elty = self.gen_lval_addr(lv)
        self.gen_expr(rv)
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
        sz, elty = self.gen_lval_addr(lv)
        self.emit('DUP')
        self.emit(loadop(sz))
        self.gen_expr(rv)
        self.emit(self.binop_ir(binop, elty))
        self.emit(stopop(sz))
        self.gen_lval_addr(lv)
        self.emit(loadop(sz))
        return elty

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
