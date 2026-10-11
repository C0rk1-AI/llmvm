"""Subset-C lexer + parser for llmvm.

Grammar (per function file):
  file      := { structdef | funcdef }
  structdef := 'struct' id '{' { member } '}' ';'
  member    := typespec declarator ';'
  funcdef   := typespec declarator '(' params ')' block
             | typespec declarator '(' params ')' ';'   (forward decl:
               registers the signature; the definition follows later)
  typespec  := 'struct' id | { typename }  ('*' after declarator id allowed)
  params    := void | { param ',' } [ param | '...' ]
               variadic functions: last fixed param must be named 'nv' and
               carries the vararg count; at most 3 fixed params total
  declarator:= '*'* id { '[' num ']' }        (array dims; params decay to ptr)
  block     := '{' { stmt } '}'
  stmt      := decl | if | while | for | return | break | continue | block |
               exprstmt | ';'
  exprstmt  := expr ';'
Expression: precedence climbing, assignment only at statement/for-init level.
Casts: '(' typename ')' unary  ->  ('cast', base, e)
Members: base '.' id | base '->' id  ->  ('member', base, name, deref)
"""
import re

TYPE_KWS = {
    'void', 'char', 'short', 'int', 'long', 'unsigned', 'signed', 'const',
    'static', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'int8_t', 'int16_t', 'int32_t', 'int64_t', 'size_t',
    'float', 'double', 'struct',
}

BASE_MAP = [
    # (ordered keyword sequence -> (base, size))
    (('unsigned', 'char'), ('u8', 1)), (('char',), ('i8', 1)),
    (('unsigned', 'short'), ('u16', 2)), (('short',), ('i16', 2)),
    (('unsigned', 'int'), ('u32', 4)), (('int',), ('i32', 4)),
    (('unsigned', 'long'), ('u64', 8)), (('long', 'long'), ('i64', 8)),
    (('unsigned',), ('u32', 4)), (('long',), ('i64', 8)),
    (('uint8_t',), ('u8', 1)), (('uint16_t',), ('u16', 2)),
    (('uint32_t',), ('u32', 4)), (('uint64_t',), ('u64', 8)),
    (('int8_t',), ('i8', 1)), (('int16_t',), ('i16', 2)),
    (('int32_t',), ('i32', 4)), (('int64_t',), ('i64', 8)),
    (('size_t',), ('u64', 8)),
    (('double',), ('f64', 8)), (('float',), ('f32', 4)),
]

BASE_SIZES = {'u8': 1, 'i8': 1, 'u16': 2, 'i16': 2, 'u32': 4, 'i32': 4,
              'u64': 8, 'i64': 8, 'f32': 4, 'f64': 8, 'void': 8}

UNSIGNED_BASES = {'u8', 'u16', 'u32', 'u64'}

TOKEN_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<fnum>\d+\.\d*(?:[eE][+-]?\d+)?[fFlL]?|\d*\.\d+(?:[eE][+-]?\d+)?[fFlL]?|\d+(?:[eE][+-]?\d+)[fFlL]?|\d+[fF])
  | (?P<num>0[xX][0-9a-fA-F]+[uUlL]*|\d+[uUlL]*)
  | (?P<chr>L?'(\\.|[^'\\])')
  | (?P<str>L?"(\\.|[^"\\])*")
  | (?P<id>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op>\.\.\.|<<=|>>=|<<|>>|<=|>=|==|!=|&&|\|\||\+=|-=|\*=|/=|%=|&=|\|=|\^=|\+\+|->|[-+*/%&|^!~<>=(),;{}\[\]\.])
""", re.VERBOSE)


class Tok:
    __slots__ = ('kind', 'val', 'line')
    def __init__(self, kind, val, line):
        self.kind, self.val, self.line = kind, val, line
    def __repr__(self):
        return f'{self.kind}:{self.val!r}'


def strip_comments(src):
    """Remove /*...*/ and //... comments, preserving newlines for errors."""
    out = []
    i, n = 0, len(src)
    while i < n:
        if src.startswith('/*', i):
            j = src.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append('\n' * src.count('\n', i, j))
            i = j
        elif src.startswith('//', i):
            j = src.find('\n', i)
            j = n if j < 0 else j
            i = j
        else:
            out.append(src[i])
            i += 1
    return ''.join(out)


def tokenize(src):
    src = strip_comments(src)
    toks, pos, line = [], 0, 1
    while pos < len(src):
        m = TOKEN_RE.match(src, pos)
        if not m:
            raise SyntaxError(f'line {line}: cannot tokenize at {src[pos:pos+30]!r}')
        pos = m.end()
        kind = m.lastgroup
        text = m.group()
        if kind == 'ws':
            line += text.count('\n')
            continue
        if kind == 'fnum':
            body = text.rstrip('fFlL')
            is32 = text[-1:] in ('f', 'F')
            toks.append(Tok('fnum', (float(body), is32), line))
        elif kind == 'num':
            v = int(text.rstrip('uUlL'), 0)
            toks.append(Tok('num', v & 0xFFFFFFFFFFFFFFFF, line))
        elif kind == 'chr':
            body = text[1:-1]
            sv = body[1:] if body.startswith('\\') else body
            esc = {'n': 10, 't': 9, 'r': 13, '0': 0, '\\': 92, "'": 39, '"': 34}
            v = esc.get(sv, ord(sv)) if body.startswith('\\') else ord(body)
            toks.append(Tok('num', v & 0xFF, line))
        elif kind == 'str':
            body = text[1:-1]
            out, i = [], 0
            while i < len(body):
                if body[i] == '\\' and i + 1 < len(body):
                    c = body[i+1]
                    out.append({'n': '\n', 't': '\t', 'r': '\r', '\\': '\\',
                                '"': '"', '0': '\0'}.get(c, c))
                    i += 2
                else:
                    out.append(body[i]); i += 1
            toks.append(Tok('str', ''.join(out), line))
        elif kind == 'id':
            toks.append(Tok('id', text, line))
        else:
            toks.append(Tok('op', text, line))
    toks.append(Tok('eof', None, line))
    return toks


# ---------------- types ----------------

class Ty:
    """base: 'u8'|...|'f64'|'struct'|'void'; ptr: depth.
    sname/sdef: struct tag and its StructDef (aggregate layout).
    stride: element stride in bytes for decayed array pointers (defaults to
    the pointed-to type's size when None).
    adims: remaining dims below the first for a decayed multi-dim array
    pointer (e.g. int32_t[4][8] decays to ptr with adims=(8,), stride=32);
    indexing peels one level at a time."""
    __slots__ = ('base', 'ptr', 'sname', 'sdef', 'stride', 'adims')
    def __init__(self, base, ptr=0, sname=None, sdef=None, stride=None,
                 adims=None):
        self.base, self.ptr = base, ptr
        self.sname, self.sdef = sname, sdef
        self.stride, self.adims = stride, adims
    def is_ptr(self):
        return self.ptr > 0
    def size(self):
        if self.ptr:
            return 8
        if self.base == 'struct':
            if self.sdef is None:
                raise SyntaxError(f'undefined struct {self.sname!r}')
            return self.sdef.size
        return BASE_SIZES[self.base]
    def esize(self):
        """Element size: size of pointed-to base (what scaling/deref uses)."""
        if self.stride is not None:
            return self.stride
        if self.ptr > 1:
            return 8
        if self.base == 'struct':
            if self.sdef is None:
                raise SyntaxError(f'undefined struct {self.sname!r}')
            return self.sdef.size
        return BASE_SIZES[self.base]
    def is_float(self):
        return self.ptr == 0 and self.base in ('f32', 'f64')
    def is_unsigned(self):
        return self.ptr > 0 or self.base in UNSIGNED_BASES
    def clone(self, ptr=None):
        return Ty(self.base, self.ptr if ptr is None else ptr,
                  self.sname, self.sdef, self.stride, self.adims)
    def __repr__(self):
        s = self.base + '*' * self.ptr
        if self.sname:
            s += f'({self.sname})'
        if self.stride is not None:
            s += f'/{self.stride}'
        return s


class StructDef:
    """MSVC-default layout: natural member alignment, tail padding."""
    __slots__ = ('name', 'members', 'size', 'align')
    def __init__(self, name, members):
        # members: [(name, ty, dims-or-None)]
        self.name = name
        off, al = 0, 1
        out = []
        for mname, mty, mdims in members:
            esz = mty.size()
            mal = self.align_of(mty)
            cnt = 1
            for d in (mdims or ()):
                cnt *= d
            off = (off + mal - 1) // mal * mal
            out.append((mname, mty, mdims, off))
            off += esz * cnt
            al = max(al, mal)
        self.align = al
        self.size = (off + al - 1) // al * al
        self.members = out

    @staticmethod
    def align_of(ty):
        if ty.ptr:
            return 8
        if ty.base == 'struct':
            return ty.sdef.align if ty.sdef else 8
        return BASE_SIZES[ty.base]

    def field(self, name):
        for m, ty, dims, off in self.members:
            if m == name:
                return ty, dims, off
        raise SyntaxError(f'struct {self.name} has no field {name!r}')


class Func:
    __slots__ = ('name', 'ret', 'params', 'body', 'line', 'variadic')
    def __init__(self, name, ret, params, body, line, variadic=False):
        self.name, self.ret, self.params = name, ret, params
        self.body, self.line, self.variadic = body, line, variadic


class Parser:
    def __init__(self, toks):
        self.toks = toks
        self.i = 0
        self.structs = {}     # tag -> StructDef

    def peek(self, k=0):
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def next(self):
        t = self.toks[self.i]
        self.i += 1
        return t

    def accept(self, val):
        t = self.peek()
        if (t.kind == 'op' and t.val == val) or (t.kind == 'id' and t.val == val):
            return self.next()
        return None

    def expect(self, val):
        t = self.next()
        if t.kind == 'op' and t.val != val:
            raise SyntaxError(f'line {t.line}: expected {val!r}, got {t.val!r}')
        if not ((t.kind == 'op' or t.kind == 'id') and t.val == val):
            raise SyntaxError(f'line {t.line}: expected {val!r}, got {t.val!r}')
        return t

    def at_typename(self):
        t = self.peek()
        return t.kind == 'id' and t.val in TYPE_KWS

    # ---------------- types ----------------

    def parse_type(self):
        t0 = self.peek()
        if t0.kind == 'id' and t0.val == 'struct':
            self.next()
            tag = self.next()
            if tag.kind != 'id':
                raise SyntaxError(f'line {tag.line}: expected struct tag')
            return Ty('struct', 0, sname=tag.val, sdef=self.structs.get(tag.val))
        kws = []
        while self.at_typename():
            kws.append(self.next().val)
        if not kws:
            t = self.peek()
            raise SyntaxError(f'line {t.line}: expected type, got {t.val!r}')
        core = tuple(k for k in kws if k not in ('const', 'static'))
        for seq, (bname, _sz) in BASE_MAP:
            if core == seq:
                return Ty(bname)
        raise SyntaxError(f'unsupported type {kws}')

    def parse_declarator(self, ty):
        """Returns (ty, name, dims); dims None unless '[N]' suffixes follow."""
        while self.accept('*'):
            ty = Ty(ty.base, ty.ptr + 1, ty.sname, ty.sdef, ty.stride)
        t = self.next()
        if t.kind != 'id':
            raise SyntaxError(f'line {t.line}: expected identifier')
        dims = None
        while self.accept('['):
            d = self.next()
            if d.kind != 'num' or d.val <= 0:
                raise SyntaxError(f'line {d.line}: array size must be a '
                                  f'positive integer constant')
            dims = (dims or []) + [d.val]
            self.expect(']')
        return ty, t.val, dims

    # ---------------- top level ----------------

    def parse_file(self):
        funcs = []
        while self.peek().kind != 'eof':
            if self.accept(';'):
                continue
            t = self.peek()
            if (t.kind == 'id' and t.val == 'struct'
                    and self.peek(1).kind == 'id'
                    and self.peek(2).kind == 'op' and self.peek(2).val == '{'):
                self.parse_struct_def()
                continue
            f = self.parse_func()
            if f is not None:      # forward declarations yield None
                funcs.append(f)
        return funcs

    def parse_struct_def(self):
        self.expect('struct')
        tag = self.next()
        if tag.kind != 'id':
            raise SyntaxError(f'line {tag.line}: expected struct tag')
        self.expect('{')
        members = []
        while not self.accept('}'):
            mty = self.parse_type()
            mty, mname, mdims = self.parse_declarator(mty)
            if mty.base == 'void' and mty.ptr == 0:
                raise SyntaxError(f'line {tag.line}: void field {mname!r}')
            if mty.base == 'struct' and mty.sdef is None:
                raise SyntaxError(f'line {tag.line}: undefined struct '
                                  f'{mty.sname!r} (define it first)')
            members.append((mname, mty, mdims))
            self.expect(';')
        self.expect(';')
        self.structs[tag.val] = StructDef(tag.val, members)

    def parse_func(self):
        line = self.peek().line
        ret = self.parse_type()
        while self.accept('*'):
            ret = Ty(ret.base, ret.ptr + 1, ret.sname, ret.sdef, ret.stride)
        t = self.next()
        if t.kind != 'id':
            raise SyntaxError(f'line {t.line}: expected function name')
        name = t.val
        self.expect('(')
        params = []
        variadic = False
        if not self.accept(')'):
            while True:
                if self.accept('...'):
                    if not params:
                        raise SyntaxError(f'line {t.line}: variadic function '
                                          f'needs at least one fixed param')
                    variadic = True
                    self.expect(')')
                    break
                pty = self.parse_type()
                pty, pname, pdims = self.parse_declarator(pty)
                if pdims is not None:      # array params decay (T a[N][M] ->
                    esz = pty.size()       # T* with the lower dims kept)
                    rest = pdims[1:]
                    pty = pty.clone(ptr=pty.ptr + 1)
                    if rest:
                        prod = 1
                        for d in rest:
                            prod *= d
                        pty.adims = tuple(rest)
                        pty.stride = esz * prod
                if pty.base == 'void' and pty.ptr == 0:
                    pname = '_'
                params.append((pty, pname))
                if self.accept(','):
                    continue
                self.expect(')')
                break
        if variadic:
            if len(params) > 3:
                raise SyntaxError(f'line {t.line}: variadic function needs '
                                  f'<= 3 fixed params (rv slots)')
            if params[-1][1] != 'nv':
                raise SyntaxError(f'line {t.line}: variadic function\'s last '
                                  f'fixed param must be named "nv" (vararg count)')
        if self.accept(';'):
            return None            # forward declaration; the def follows later
        body = self.parse_block()
        return Func(name, ret, params, body, line, variadic)

    # ---------------- statements ----------------

    def parse_block(self):
        self.expect('{')
        stmts = []
        while not self.accept('}'):
            stmts.append(self.parse_stmt())
        return ('block', stmts)

    def parse_stmt(self):
        t = self.peek()
        if t.kind == 'op' and t.val == '{':
            return self.parse_block()
        if t.kind == 'op' and t.val == ';':
            self.next()
            return ('empty',)
        if t.kind == 'id':
            if t.val == 'if':
                return self.parse_if()
            if t.val == 'while':
                return self.parse_while()
            if t.val == 'for':
                return self.parse_for()
            if t.val == 'return':
                self.next()
                if self.accept(';'):
                    return ('return', None)
                e = self.parse_assign_expr()
                self.expect(';')
                return ('return', e)
            if t.val == 'break':
                self.next(); self.expect(';')
                return ('break',)
            if t.val == 'continue':
                self.next(); self.expect(';')
                return ('continue',)
            if t.val in TYPE_KWS:
                # declaration(s) — comma-separated declarators, one init max
                ty0 = self.parse_type()
                decls = []
                while True:
                    ty, name, dims = self.parse_declarator(ty0.clone())
                    init = None
                    if self.accept('='):
                        init = self.parse_assign_expr()
                    d = ('decl', ty, name, init)
                    if dims is not None:
                        d = d + (dims,)
                    decls.append(d)
                    if self.accept(','):
                        continue
                    break
                self.expect(';')
                if len(decls) == 1:
                    return decls[0]
                return ('multidecl', decls)
        # expression statement
        e = self.parse_assign_expr()
        self.expect(';')
        return ('expr', e)

    def parse_if(self):
        self.expect('if'); self.expect('(')
        c = self.parse_expr()
        self.expect(')')
        th = self.parse_stmt()
        el = None
        if self.accept('else'):
            el = self.parse_stmt()
        return ('if', c, th, el)

    def parse_while(self):
        self.expect('while'); self.expect('(')
        c = self.parse_expr()
        self.expect(')')
        b = self.parse_stmt()
        return ('while', c, b)

    def parse_for(self):
        self.expect('for'); self.expect('(')
        if self.accept(';'):
            init = None
        elif self.at_typename():
            ty = self.parse_type()
            ty, name, dims = self.parse_declarator(ty)
            if dims is not None:
                raise SyntaxError('array decl not allowed in for-init')
            init = None
            if self.accept('='):
                init = self.parse_assign_expr()
            self.expect(';')
            init = ('decl', ty, name, init)
        else:
            init = ('expr', self.parse_assign_expr())
            self.expect(';')
        cond = None
        if not self.accept(';'):
            cond = self.parse_expr()
            self.expect(';')
        step = None
        if not self.accept(')'):
            step = self.parse_assign_expr()
            self.expect(')')
        body = self.parse_stmt()
        return ('for', init, cond, step, body)

    # ---------------- expressions ----------------

    def parse_expr(self):
        e = self.parse_assign_expr()
        return e

    def parse_assign_expr(self):
        lhs = self.parse_binary(0)
        t = self.peek()
        if t.kind == 'op' and t.val in ('=', '+=', '-=', '*=', '/=', '%=',
                                        '&=', '|=', '^=', '<<=', '>>='):
            self.next()
            rhs = self.parse_assign_expr()
            if t.val == '=':
                return ('assign', lhs, rhs)
            return ('assignop', t.val[:-1], lhs, rhs)
        return lhs

    BINOPS = [
        ['||'], ['&&'], ['|'], ['^'], ['&'],
        ['==', '!='], ['<', '>', '<=', '>='], ['<<', '>>'],
        ['+', '-'], ['*', '/', '%'],
    ]

    def parse_binary(self, lvl):
        if lvl >= len(self.BINOPS):
            return self.parse_unary()
        e = self.parse_binary(lvl + 1)
        while True:
            t = self.peek()
            if t.kind == 'op' and t.val in self.BINOPS[lvl]:
                self.next()
                r = self.parse_binary(lvl + 1)
                e = ('bin', t.val, e, r)
            else:
                return e

    def parse_unary(self):
        t = self.peek()
        if t.kind == 'op' and t.val in ('-', '!', '~', '*'):
            self.next()
            return ('un', t.val, self.parse_unary())
        if t.kind == 'op' and t.val == '(':
            # cast?
            if self.peek(1).kind == 'id' and self.peek(1).val in TYPE_KWS:
                save = self.i
                self.next()  # (
                ty = self.parse_type()
                depth = 0
                while self.accept('*'):
                    depth += 1
                if self.accept(')'):
                    e = self.parse_unary()
                    return ('cast', Ty(ty.base, depth, ty.sname, ty.sdef), e)
                self.i = save
        return self.parse_postfix()

    def parse_postfix(self):
        e = self.parse_primary()
        while True:
            t = self.peek()
            if t.kind == 'op' and t.val == '(':
                self.next()
                args = []
                if not self.accept(')'):
                    while True:
                        args.append(self.parse_assign_expr())
                        if self.accept(','):
                            continue
                        self.expect(')')
                        break
                e = ('call', e, args)
            elif t.kind == 'op' and t.val == '[':
                self.next()
                idx = self.parse_expr()
                self.expect(']')
                e = ('index', e, idx)
            elif t.kind == 'op' and t.val in ('.', '->'):
                self.next()
                m = self.next()
                if m.kind != 'id':
                    raise SyntaxError(f'line {m.line}: expected member name')
                e = ('member', e, m.val, t.val == '->')
            else:
                return e

    def parse_primary(self):
        t = self.next()
        if t.kind == 'num':
            return ('num', t.val)
        if t.kind == 'fnum':
            return ('fnum', t.val[0], t.val[1])
        if t.kind == 'str':
            return ('str', t.val)
        if t.kind == 'op' and t.val == '(':
            e = self.parse_expr()
            self.expect(')')
            return e
        if t.kind == 'id':
            if self.peek().kind == 'op' and self.peek().val == '(':
                return ('varfn', t.val)
            return ('var', t.val)
        raise SyntaxError(f'line {t.line}: unexpected token {t.val!r}')


def parse(src):
    """Legacy entry: returns the function list only."""
    return Parser(tokenize(src)).parse_file()


def parse_full(src):
    """Returns (funcs, structs): struct tag -> StructDef."""
    p = Parser(tokenize(src))
    funcs = p.parse_file()
    return funcs, p.structs


def _ty_feat(ty, feats):
    if ty.base in ('f32', 'f64'):
        feats.add('float')
    elif ty.base == 'struct':
        feats.add('struct')


def scan_features(funcs, structs=None):
    """Feature set used by the build (gates new opcode aliases / VM fields;
    builds without these features keep the legacy rng draw sequence)."""
    feats = set()
    if structs:
        feats.add('struct')
        for sd in structs.values():
            for _n, mty, mdims, _o in sd.members:
                _ty_feat(mty, feats)
                if mdims:
                    feats.add('narray')

    def expr(e):
        if isinstance(e, tuple):
            k = e[0]
            if k == 'fnum':
                feats.add('float')
            elif k == 'member':
                feats.add('struct')
            elif k == 'decl':
                _ty_feat(e[1], feats)
                if len(e) > 4 and e[4]:
                    feats.add('narray')
            elif k == 'cast' and isinstance(e[1], Ty):
                _ty_feat(e[1], feats)
            for x in e[1:]:
                expr(x)
        elif isinstance(e, list):
            for x in e:
                expr(x)

    for fn in funcs:
        if fn.variadic:
            feats.add('varargs')
        _ty_feat(fn.ret, feats)
        for pty, _pn in fn.params:
            _ty_feat(pty, feats)
        expr(fn.body)
    return feats
