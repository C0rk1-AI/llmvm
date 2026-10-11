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
