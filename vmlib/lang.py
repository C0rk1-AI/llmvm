"""Subset-C lexer + parser for llmvm.

Grammar (per function file):
  file      := { funcdef }
  funcdef   := typespec declarator '(' params ')' block
             | typespec declarator '(' params ')' ';'   (forward decl:
               registers the signature; the definition follows later)
  typespec  := { typename }  ('*' after declarator id allowed)
  block     := '{' { stmt } '}'
  stmt      := decl | if | while | for | return | break | continue | block |
               exprstmt | ';'
  exprstmt  := expr ';'
Expression: precedence climbing, assignment only at statement/for-init level.
Casts: '(' typename ')' unary  ->  ('cast', base, e)
"""
import re

TYPE_KWS = {
    'void', 'char', 'short', 'int', 'long', 'unsigned', 'signed', 'const',
    'static', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'int8_t', 'int16_t', 'int32_t', 'int64_t', 'size_t',
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
]

UNSIGNED_BASES = {'u8', 'u16', 'u32', 'u64'}

TOKEN_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<num>0[xX][0-9a-fA-F]+[uUlL]*|\d+[uUlL]*)
  | (?P<chr>L?'(\\.|[^'\\])')
  | (?P<str>L?"(\\.|[^"\\])*")
  | (?P<id>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op><<=|>>=|<<|>>|<=|>=|==|!=|&&|\|\||\+=|-=|\*=|/=|%=|&=|\|=|\^=|\+\+|->|[-+*/%&|^!~<>=(),;{}\[\]\.])
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
        if kind == 'num':
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
    """base: 'u8'|'i8'|'u16'|'i16'|'u32'|'i32'|'u64'|'i64'|'void'; ptr: depth."""
    __slots__ = ('base', 'ptr')
    def __init__(self, base, ptr=0):
        self.base, self.ptr = base, ptr
    def is_ptr(self):
        return self.ptr > 0
    def size(self):
        if self.ptr:
            return 8
        return {'u8': 1, 'i8': 1, 'u16': 2, 'i16': 2, 'u32': 4,
                'i32': 4, 'u64': 8, 'i64': 8, 'void': 8}[self.base]
    def esize(self):
        """Element size: size of pointed-to base (what scaling/deref uses)."""
        return {'u8': 1, 'i8': 1, 'u16': 2, 'i16': 2, 'u32': 4,
                'i32': 4, 'u64': 8, 'i64': 8, 'void': 8}[self.base]
    def is_unsigned(self):
        return self.ptr > 0 or self.base in UNSIGNED_BASES
    def clone(self, ptr=None):
        return Ty(self.base, self.ptr if ptr is None else ptr)
    def __repr__(self):
        return self.base + '*' * self.ptr


class Func:
    __slots__ = ('name', 'ret', 'params', 'body', 'line')
    def __init__(self, name, ret, params, body, line):
        self.name, self.ret, self.params, self.body, self.line = name, ret, params, body, line


class Parser:
    def __init__(self, toks):
        self.toks = toks
        self.i = 0

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
        if (t.kind == 'op' and t.val != val) or not (
            (t.kind == 'op' or t.kind == 'id') and t.val == val):
            raise SyntaxError(f'line {t.line}: expected {val!r}, got {t.val!r}')
        return t

    def at_typename(self):
        t = self.peek()
        return t.kind == 'id' and t.val in TYPE_KWS

    # ---------------- types ----------------

    def parse_type(self):
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
        while self.accept('*'):
            ty = Ty(ty.base, ty.ptr + 1)
        t = self.next()
        if t.kind != 'id':
            raise SyntaxError(f'line {t.line}: expected identifier')
        return ty, t.val

    # ---------------- top level ----------------

    def parse_file(self):
        funcs = []
        while self.peek().kind != 'eof':
            if self.accept(';'):
                continue
            f = self.parse_func()
            if f is not None:      # forward declarations yield None
                funcs.append(f)
        return funcs

    def parse_func(self):
        line = self.peek().line
        ret = self.parse_type()
        while self.accept('*'):
            ret = Ty(ret.base, ret.ptr + 1)
        t = self.next()
        if t.kind != 'id':
            raise SyntaxError(f'line {t.line}: expected function name')
        name = t.val
        self.expect('(')
        params = []
        if not self.accept(')'):
            while True:
                if self.accept('...'):
                    raise SyntaxError('variadic virtualized functions not supported')
                pty = self.parse_type()
                pty, pname = self.parse_declarator(pty)
                if pty.base == 'void' and pty.ptr == 0:
                    pname = '_'
                params.append((pty, pname))
                if self.accept(','):
                    continue
                self.expect(')')
                break
        if self.accept(';'):
            return None            # forward declaration; the def follows later
        body = self.parse_block()
        return Func(name, ret, params, body, line)

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
                    ty, name = self.parse_declarator(ty0.clone())
                    init = None
                    if self.accept('='):
                        init = self.parse_assign_expr()
                    decls.append(('decl', ty, name, init))
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
            ty, name = self.parse_declarator(ty)
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
                    return ('cast', Ty(ty.base, depth), e)
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
            else:
                return e

    def parse_primary(self):
        t = self.next()
        if t.kind == 'num':
            return ('num', t.val)
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
    return Parser(tokenize(src)).parse_file()
