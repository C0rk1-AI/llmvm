#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint64_t t_arith(uint64_t a, uint64_t b);
uint64_t t_ctrl(uint64_t n);
uint32_t t_logic(uint32_t a, uint32_t b);
uint64_t t_ptr(uint8_t* buf, uint64_t n);
uint32_t t_str(const char* s);
uint32_t t_helper(uint32_t x);
uint32_t t_vmcall(uint32_t seed, uint64_t rounds);
uint32_t t_casts(uint64_t big);
uint64_t t_mem_rw(uint64_t* slots, uint64_t n);
uint32_t t_hostmix(const char* tag, uint32_t v);
uint64_t t_cmp(uint64_t a, uint64_t b);
int32_t t_narrow(int32_t a, int16_t b, uint32_t c);
uint32_t t_recfact(uint32_t n);
uint32_t t_recfib(uint32_t n);
uint64_t t_recsum(uint64_t n);
uint32_t t_muteven(uint32_t n);
uint32_t t_mutodd(uint32_t n);
double t_fmath(double a, double b);
float t_f32acc(float x, uint32_t n);
double t_fcond(double x);
uint64_t t_fconv(uint32_t sel);
double t_fsumd(double* v, uint32_t n);
float t_fsumf(float* v, uint32_t n);
uint32_t t_fprint(const char* tag, double v, float w);
double t_fsqrt(double x);
struct Vec3 { float x; float y; float z; };
struct Node { struct Vec3 pos; uint32_t id; double w; uint8_t tag[4]; };
struct Board { uint32_t base; uint8_t cells[4][8]; uint64_t total; };
double t_node_sum(struct Node* ns, uint32_t n);
uint32_t t_node_fill(struct Node* ns, uint32_t n, uint32_t seed);
uint32_t t_node_local(uint32_t seed);
uint32_t t_board(struct Board* b, uint32_t seed);
int32_t t_grid2d(uint32_t n);
uint32_t t_cube3d(uint32_t seed);
uint64_t t_larr1(uint32_t n);
uint32_t t_gridp(int32_t g[4][8], uint32_t mult);
uint64_t vsum(uint64_t nv, ...);
uint64_t vmax(uint64_t nv, ...);
uint64_t vmix(uint64_t nv, ...);
uint64_t vrec(uint64_t depth, uint64_t nv, ...);
uint64_t t_vcall(uint32_t sel);

int main(void) {
  uint64_t i;
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("%llu\n", (unsigned long long)t_arith(123456789, 987654321));
  printf("%llu\n", (unsigned long long)t_ctrl(30));
  printf("%u\n", t_logic(0xF0F0A5A5u, 0x0F0F5A5Au));
  {
    uint8_t b[16];
    for (i = 0; i < 16; i++) b[i] = (uint8_t)(i * 17 + 3);
    printf("%llu\n", (unsigned long long)t_ptr(b, 16));
    for (i = 0; i < 16; i++) printf("%02x", b[i]);
    printf("\n");
  }
  printf("%u\n", t_str("hello, LLM-vm world!"));
  printf("%u\n", t_vmcall(0x1234567, 10));
  printf("%u\n", t_casts(0x1122334455667788ull));
  {
    uint64_t s[4] = {1, 2, 3, 4};
    printf("%llu\n", (unsigned long long)t_mem_rw(s, 4));
    printf("%llu %llu %llu\n", (unsigned long long)s[0],
           (unsigned long long)s[1], (unsigned long long)s[3]);
  }
  t_hostmix("sect", 48879u);
  printf("%llu %llu %llu\n", (unsigned long long)t_cmp(3, 9),
         (unsigned long long)t_cmp(9, 3),
         (unsigned long long)t_cmp(18446744073709551615ull, 4));
  printf("%d %d %d\n", t_narrow(-1234567, -321, 4000000000u),
         t_narrow(987654, 12345, 7),
         t_narrow(-2147483647 - 1, -1, 4294967295u));
  printf("%u %u %llu\n", t_recfact(12u), t_recfib(22u),
         (unsigned long long)t_recsum(9876543210123ull));
  printf("%u %u %u %u\n", t_muteven(10u), t_mutodd(10u),
         t_muteven(7u), t_mutodd(7u));
  /* ---- float ---- */
  printf("%.6f\n", t_fmath(3.75, -0.5));
  printf("%.6f\n", t_fmath(-1e-3, 2.0));
  printf("%.6f\n", (double)t_f32acc(0.1f, 9u));
  printf("%.6f\n", (double)t_f32acc(-3.9f, 15u));
  printf("%.1f\n", t_fcond(0.75));
  printf("%.1f\n", t_fcond(-1e9));
  printf("%llu %llu %llu %llu\n", (unsigned long long)t_fconv(0u),
         (unsigned long long)t_fconv(1u), (unsigned long long)t_fconv(2u),
         (unsigned long long)t_fconv(3u));
  printf("%llu %llu %llu %llu %llu\n", (unsigned long long)t_fconv(4u),
         (unsigned long long)t_fconv(5u), (unsigned long long)t_fconv(6u),
         (unsigned long long)t_fconv(7u), (unsigned long long)t_fconv(8u));
  {
    double dv[5] = {0.1, 0.35, -2.5, 1e10, 0.0};
    float fv[4] = {0.1f, -0.75f, 3.5f, 1e-3f};
    printf("%.6f\n", t_fsumd(dv, 5u));
    printf("%.6f\n", (double)t_fsumf(fv, 4u));
  }
  t_fprint("fp", 2.0 / 3.0, 1.0f / 3.0f);
  printf("%.9f\n", t_fsqrt(2.0));
  /* ---- struct ---- */
  {
    struct Node ns[4];
    uint32_t k;
    for (k = 0; k < 4u; k++) {
      ns[k].pos.x = (float)k; ns[k].pos.y = 0.5f; ns[k].pos.z = 0.0f;
      ns[k].id = k * 3u; ns[k].w = (double)k * 0.25;
      ns[k].tag[0] = 1; ns[k].tag[1] = 2; ns[k].tag[2] = 3; ns[k].tag[3] = 4;
    }
    printf("%u\n", t_node_fill(ns, 4u, 12345u));
    printf("%.6f\n", t_node_sum(ns, 4u));
    printf("%llu %u\n",
           (unsigned long long)(ns[2].id + (uint64_t)ns[2].tag[0]),
           t_node_local(77u));
  }
  {
    struct Board b;
    memset(&b, 0, sizeof b);
    printf("%u %llu\n", t_board(&b, 9u), (unsigned long long)b.total);
    printf("%u %u\n", (uint32_t)b.cells[2][3], (uint32_t)b.cells[0][7]);
  }
  /* ---- multi-dim arrays ---- */
  printf("%d\n", t_grid2d(5u));
  printf("%u\n", t_cube3d(33u));
  printf("%llu\n", (unsigned long long)t_larr1(7u));
  {
    int32_t g[4][8];
    int r, c;
    for (r = 0; r < 4; r++)
      for (c = 0; c < 8; c++) g[r][c] = r * 10 + c;
    printf("%u\n", t_gridp(g, 3u));
    printf("%d %d\n", g[3][7], g[0][1]);
  }
  /* ---- variadic: VM->VM callers, then native->VM wrapper entry ---- */
  printf("%llu\n", (unsigned long long)t_vcall(0u));
  printf("%llu\n", (unsigned long long)t_vcall(1u));
  printf("%llu\n", vsum(3ull, 10ull, 20ull, 30ull));
  printf("%llu\n", (unsigned long long)vmax(5ull, 3ull, 99ull, 1ull,
                                            50ull, 7ull));
  return 0;
}
