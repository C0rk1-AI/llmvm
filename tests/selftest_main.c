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
  return 0;
}
