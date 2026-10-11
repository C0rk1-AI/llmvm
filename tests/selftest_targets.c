uint64_t t_arith(uint64_t a, uint64_t b) {
  uint64_t r;
  a += 1;
  b -= 2;
  a *= 3;
  r = (a + b) * 3 - (b / 2) + (a % 7);
  r ^= (a << 3);
  r |= (b >> 5);
  r %= 1000003;
  return r;
}

uint64_t t_ctrl(uint64_t n) {
  uint64_t s; uint64_t i;
  s = 0;
  for (i = 0; i < n; i = i + 1) {
    if ((i % 2) == 0) { s = s + i * i; }
    else if (i % 3 == 0) { s = s + 1; }
    else { s = s - 2; }
    if (i == 4) { break; }
  }
  i = 0;
  while (i < 100) {
    i = i + 7;
    if (i == 21) { continue; }
    s = s + i;
    if (i > 50) { break; }
  }
  return s;
}

uint32_t t_logic(uint32_t a, uint32_t b) {
  uint32_t r;
  r = (uint32_t)(a & b) | (uint32_t)(~a ^ b);
  if (a && b) { r = (uint32_t)(r + 1); }
  if (!a || !b) { r = (uint32_t)(r + 2); }
  if (!(a == b)) { r = (uint32_t)(r + 4); }
  r = (uint32_t)(r << 9);
  r = (uint32_t)(r >> 3);
  return r;
}

uint64_t t_ptr(uint8_t* buf, uint64_t n) {
  uint64_t i; uint64_t acc;
  acc = 0;
  for (i = 0; i < n; i = i + 1) {
    buf[i] = (uint8_t)(buf[i] ^ 0x5A);
  }
  for (i = 0; i < n; i = i + 1) {
    acc = acc * 31 + buf[i];
  }
  return acc;
}

uint32_t t_str(const char* s) {
  uint64_t n; uint32_t h; uint64_t i;
  n = strlen(s);
  h = 0x1505u;
  for (i = 0; i < n; i = i + 1) {
    h = (uint32_t)((h << 5) + h + (uint32_t)s[i]);
  }
  return h;
}

uint32_t t_helper(uint32_t x) {
  x = (uint32_t)(x ^ 0x9E3779B9);
  x = (uint32_t)(x * 0x85EBCA6B);
  x = (uint32_t)(x ^ (x >> 13));
  return x;
}

uint32_t t_vmcall(uint32_t seed, uint64_t rounds) {
  uint32_t h; uint64_t i;
  h = seed;
  for (i = 0; i < rounds; i = i + 1) {
    h = t_helper(h);
    h = (uint32_t)(h + (uint32_t)i);
  }
  return h;
}

uint32_t t_casts(uint64_t big) {
  uint8_t a; uint16_t b; uint32_t c;
  a = (uint8_t)big;
  b = (uint16_t)(big >> 8);
  c = (uint32_t)(big >> 16);
  return (uint32_t)((uint32_t)a + (uint32_t)b + c);
}

uint64_t t_mem_rw(uint64_t* slots, uint64_t n) {
  uint64_t i;
  for (i = 0; i < n; i = i + 1) { slots[i] = slots[i] * 3 + i; }
  return slots[n - 1];
}

uint32_t t_hostmix(const char* tag, uint32_t v) {
  printf("[%s] %08x\n", tag, v);
  puts("put");
  return (uint32_t)(v + 7);
}

uint64_t t_cmp(uint64_t a, uint64_t b) {
  uint64_t r;
  r = 0;
  if (a < b) { r = r + 1; }
  if (a > b) { r = r + 3; }
  if (a <= b) { r = r + 7; }
  if (a >= b) { r = r + 11; }
  if (a == b) { r = r + 17; }
  if (a != b) { r = r + 23; }
  if (a + 1 > b) { r = r * 31 + 2; }
  if (b - 1 < a) { r = r * 37 + 5; }
  return r;
}

int32_t t_narrow(int32_t a, int16_t b, uint32_t c) {
  int32_t h;
  int8_t s;
  int16_t t;
  h = a / 3 - b % 7;
  h = (int32_t)(h << 3) + (a >> 2);
  s = (int8_t)(h ^ 0x5A);
  t = (int16_t)(h ^ 0x2C4);
  h = h + s * 1000 + t * 7;
  if (h < a) { h = h - c; } else { h = (int32_t)((uint32_t)h * 3u); }
  if ((int64_t)h > -100000) { h = h ^ -1; }
  h = (int32_t)(h % 1000003);
  return h;
}

/* recursion: direct self-calls (deep CALLV nesting + per-entry KSET re-key) */
uint32_t t_recfact(uint32_t n) {
  if (n <= 1u) { return 1u; }
  return n * t_recfact(n - 1u);
}

uint32_t t_recfib(uint32_t n) {
  if (n < 2u) { return n; }
  return t_recfib(n - 1u) + t_recfib(n - 2u);
}

uint64_t t_recsum(uint64_t n) {
  if (n < 10u) { return n; }
  return (n % 10u) + t_recsum(n / 10u);
}

/* mutual recursion via forward declarations */
uint32_t t_muteven(uint32_t n);
uint32_t t_mutodd(uint32_t n);

uint32_t t_muteven(uint32_t n) {
  if (n == 0u) { return 1u; }
  return t_mutodd(n - 1u);
}

uint32_t t_mutodd(uint32_t n) {
  if (n == 0u) { return 0u; }
  return t_muteven(n - 1u);
}

/* ---- float: f64 arithmetic, compound assign, compares, unary minus ---- */
double t_fmath(double a, double b) {
  double r; double acc; uint32_t i;
  r = a * 1.5 + b / 4.0 - 0.25;
  r *= 3.0;
  r -= a;
  r /= 2.5;
  acc = 0.0;
  for (i = 0; i < 6; i = i + 1) {
    acc = acc + r;
    r = -r / 8.0;
    if (r < -1.0) { acc = acc + 0.5; }
    if (acc >= 10.0) { acc = acc - 10.0; }
    if (acc != acc) { acc = 0.0; }
  }
  if (a < b) { acc = acc + 1.0; }
  if (a > b) { acc = acc + 2.0; }
  if (a + 1.0 <= b) { acc = acc + 4.0; }
  return acc;
}

/* ---- float: per-op f32 rounding (differs from f64 accumulate) ---- */
float t_f32acc(float x, uint32_t n) {
  float a; uint32_t i;
  a = x;
  for (i = 0; i < n; i = i + 1) {
    a = a + 0.1f;
    a = a * 1.1f;
    a = a - 0.05f;
  }
  a += 2.5f;
  a *= 0.5f;
  return a;
}

/* ---- float: -0.0 / truthiness / mixed-precision compare ---- */
double t_fcond(double x) {
  double r; double z; float fz;
  z = 0.0;
  r = 0.0;
  z = -z;                      /* -0.0 via sign flip */
  if (z == 0.0) { r = r + 1.0; }   /* true: -0.0 == +0.0 */
  if (!z) { r = r + 2.0; }         /* true: -0.0 is falsy */
  if (z < 0.0) { r = r + 4.0; }    /* false */
  fz = -0.0f;
  if (fz == 0.0) { r = r + 8.0; }
  if (fz < 0.0) { r = r + 16.0; }  /* false */
  if (0.5f < x) { r = r + 32.0; }  /* f32/f64 mixed compare */
  if (x >= 1e-3) { r = r + 64.0; }
  if (-x > -1e9) { r = r + 128.0; }
  return r;
}

/* ---- float: int <-> float conversion edges ---- */
uint64_t t_fconv(uint32_t sel) {
  int64_t a; uint64_t b; float f; double d; int32_t i32;
  a = (int64_t)(-3.7);         /* truncates toward zero -> -3 */
  b = (uint64_t)3.9e18;
  f = (float)16777217;         /* rounds to 16777216 */
  d = (double)f;
  i32 = (int32_t)(d / 2.0);
  if (sel == 0u) { return (uint64_t)a; }
  if (sel == 1u) { return b; }
  if (sel == 2u) { return (uint64_t)(int64_t)f; }
  if (sel == 3u) { return (uint64_t)(int64_t)d; }
  if (sel == 4u) { return (uint64_t)(int64_t)i32; }
  if (sel == 5u) { return (uint64_t)(int64_t)(float)(-5);
  }
  if (sel == 6u) { return (uint64_t)(int64_t)(double)(-7);
  }
  return (uint64_t)(int64_t)((double)a + d + (double)(float)b * 0.0);
}

/* ---- float: arrays of f64/f32 through pointers ---- */
double t_fsumd(double* v, uint32_t n) {
  double s; uint32_t i;
  s = 0.0;
  for (i = 0; i < n; i = i + 1) { s = s + v[i] * 2.0 - 0.5; }
  return s;
}

float t_fsumf(float* v, uint32_t n) {
  float s; uint32_t i;
  s = 0.0f;
  for (i = 0; i < n; i = i + 1) { s = s + v[i] * 2.0f - 0.5f; }
  return s;
}

/* ---- float: printf host path (F2D promotion at call site) ---- */
uint32_t t_fprint(const char* tag, double v, float w) {
  printf("%s %.3f\n", tag, v);
  printf("%s %.2f\n", tag, w);
  return (uint32_t)(int64_t)v;
}

/* ---- float: typed double host (sqrt) ---- */
double t_fsqrt(double x) {
  return sqrt(x) + sqrt(x * 4.0) * 0.5 + (double)(int64_t)sqrt(2.0);
}

/* ---- struct: nested defs, member arrays, struct arrays via pointer ---- */
struct Vec3 { float x; float y; float z; };
struct Node { struct Vec3 pos; uint32_t id; double w; uint8_t tag[4]; };
struct Board { uint32_t base; uint8_t cells[4][8]; uint64_t total; };

double t_node_sum(struct Node* ns, uint32_t n) {
  double s; uint32_t i; uint32_t j;
  s = 0.0;
  for (i = 0; i < n; i = i + 1) {
    ns[i].pos.x = ns[i].pos.x + 1.0f;
    ns[i].tag[0] = (uint8_t)(ns[i].tag[0] + i);
    for (j = 0; j < 4u; j = j + 1) {
      ns[i].tag[j] = (uint8_t)(ns[i].tag[j] ^ (i + j));
    }
    s = s + (double)ns[i].pos.x + (double)ns[i].pos.y
          + ns[i].w + (double)ns[i].id + (double)ns[i].tag[3];
  }
  return s;
}

uint32_t t_node_fill(struct Node* ns, uint32_t n, uint32_t seed) {
  uint32_t i; uint32_t j; uint32_t h;
  for (i = 0; i < n; i = i + 1) {
    ns[i].pos.x = (float)(i * 3 + seed);
    ns[i].pos.y = (float)(i * 7 - seed);
    ns[i].pos.z = 0.25f;
    ns[i].id = (uint32_t)(i * 2654435761u + seed);
    ns[i].w = (double)ns[i].id * 1e-3;
    for (j = 0; j < 4u; j = j + 1) {
      ns[i].tag[j] = (uint8_t)((i * 16 + j * 3 + seed) & 0xFFu);
    }
  }
  h = 0x1505u;
  for (i = 0; i < n; i = i + 1) {
    h = (uint32_t)((h << 5) + h + ns[i].id + ns[i].tag[1]);
  }
  return h;
}

uint32_t t_node_local(uint32_t seed) {
  struct Node tmp; uint32_t h; uint32_t j;
  tmp.pos.x = (float)seed;
  tmp.pos.y = 2.5f;
  tmp.pos.z = -0.5f;
  tmp.id = seed + 100u;
  tmp.w = 6.25;
  for (j = 0; j < 4u; j = j + 1) { tmp.tag[j] = (uint8_t)(seed + j); }
  h = (uint32_t)((uint32_t)tmp.pos.x + (uint32_t)tmp.pos.y * 3u
                 + tmp.id + (uint32_t)(int64_t)tmp.w + tmp.tag[2]);
  return h;
}

/* struct with a multi-dim array member */
uint32_t t_board(struct Board* b, uint32_t seed) {
  uint32_t i; uint32_t j; uint64_t s;
  b->base = seed;
  s = 0;
  for (i = 0; i < 4u; i = i + 1) {
    for (j = 0; j < 8u; j = j + 1) {
      b->cells[i][j] = (uint8_t)((i * 8u + j + seed) & 0xFFu);
      s = s * 31u + b->cells[i][j];
    }
  }
  b->total = s + b->base;
  return (uint32_t)(s ^ (s >> 32)) + b->cells[3][7];
}

/* ---- local multi-dim arrays ---- */
int32_t t_grid2d(uint32_t n) {
  int32_t g[4][8]; uint32_t i; uint32_t j; int32_t s;
  for (i = 0; i < 4u; i = i + 1) {
    for (j = 0; j < 8u; j = j + 1) {
      g[i][j] = (int32_t)((i * 31u + j * n) % 97u);
    }
  }
  s = 0;
  for (i = 0; i < 4u; i = i + 1) {
    for (j = 0; j < 8u; j = j + 1) {
      if ((i + j) % 2u == 0u) { s = s + g[i][j]; }
      else { s = s - g[i][j] * 3; }
    }
  }
  g[2][5] = s;
  return s + g[2][5] - g[0][0];
}

uint32_t t_cube3d(uint32_t seed) {
  uint8_t c[2][3][4]; uint32_t i; uint32_t j; uint32_t k; uint32_t h;
  for (i = 0; i < 2u; i = i + 1) {
    for (j = 0; j < 3u; j = j + 1) {
      for (k = 0; k < 4u; k = k + 1) {
        c[i][j][k] = (uint8_t)((i * 12u + j * 4u + k + seed) & 0xFFu);
      }
    }
  }
  h = 0x9E3779B9u;
  for (i = 0; i < 2u; i = i + 1) {
    for (j = 0; j < 3u; j = j + 1) {
      for (k = 0; k < 4u; k = k + 1) {
        h = (uint32_t)(h * 33u + c[i][j][k] + (uint32_t)(i ^ j ^ k));
      }
    }
  }
  return h;
}

/* local 1-D arrays (LAA + STn/LDn of narrow widths) */
uint64_t t_larr1(uint32_t n) {
  uint64_t a[10]; uint8_t b[10]; uint64_t s; uint32_t i;
  for (i = 0; i < 10u; i = i + 1) {
    a[i] = (uint64_t)(i + n) * 2654435761u;
    b[i] = (uint8_t)(i * 7 + n);
  }
  s = 0;
  for (i = 0; i < 10u; i = i + 1) { s = s + a[i] + b[i]; }
  return s;
}

/* multi-dim array PARAM (T g[4][8] decays to a row pointer) */
uint32_t t_gridp(int32_t g[4][8], uint32_t mult) {
  uint32_t i; uint32_t j; uint32_t h;
  h = 0;
  for (i = 0; i < 4u; i = i + 1) {
    for (j = 0; j < 8u; j = j + 1) {
      g[i][j] = (int32_t)((g[i][j] + (int32_t)(i * 8u + j)) * (int32_t)mult);
      h = (uint32_t)(h + (uint32_t)g[i][j]);
    }
  }
  return h;
}

/* ---- variadic virtual functions ---- */
uint64_t vsum(uint64_t nv, ...) {
  uint64_t s; uint64_t i;
  vv_start();
  s = 0;
  for (i = 0; i < nv; i = i + 1) { s = s + vv_next(); }
  return s;
}

uint64_t vmax(uint64_t nv, ...) {
  uint64_t m; uint64_t v; uint64_t i;
  vv_start();
  m = 0;
  for (i = 0; i < nv; i = i + 1) {
    v = vv_next();
    if (v > m) { m = v; }
  }
  return m;
}

/* variadic that consumes each vararg through a VM call */
uint64_t vmix(uint64_t nv, ...) {
  uint64_t s; uint64_t i;
  vv_start();
  s = 0;
  for (i = 0; i < nv; i = i + 1) {
    s = s * 31u + (uint64_t)t_helper((uint32_t)vv_next());
  }
  return s;
}

/* recursion + variadic: each level stages its own varargs (per-invocation
   vmst.va), and the call chain nests CALLV inside a variadic frame */
uint64_t vrec(uint64_t depth, uint64_t nv, ...) {
  uint64_t s; uint64_t i;
  vv_start();
  s = depth;
  for (i = 0; i < nv; i = i + 1) { s = s * 31u + vv_next(); }
  if (depth > 0u) { s = s + vrec(depth - 1u, 2u, s, s + 7u); }
  return s;
}

/* VM-side caller of variadic callees (varargs first, fixed params last).
   Vararg literals are 64-bit (ull): the native-side va_arg(ap, uint64_t)
   reads the full 8-byte slot, and 32-bit literals leave the upper bytes
   undefined on MSVC — 64-bit varargs are the documented convention. */
uint64_t t_vcall(uint32_t sel) {
  uint64_t r;
  r = vsum(3u, 10ull, 20ull, 30ull);
  r = r * 7u + vsum(5u, 1ull, 2ull, 3ull, 4ull, 5ull);
  r = r * 11u + vmax(4u, 9ull, 2ull, 77ull, 3ull);
  r = r * 13u + vmix(3u, 11ull, 22ull, 33ull);
  r = r * 17u + vrec(3u, 2ull, 5ull, 6ull);
  if (sel == 1u) { r = r + vsum(2u, (uint64_t)-5, 1000000000000ull); }
  return r;
}
