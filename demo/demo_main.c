/* Demo main — compiled natively in the control build, and #included into
 * protected.c (after the VM + wrappers) in the protected build.
 * The plaintext message never appears in this file: MSGC holds only the
 * rolling-XOR ciphertext; vm_decode_msg recovers it at runtime. */
#include <stdint.h>
#include <stdio.h>

uint32_t vm_decode_msg(uint8_t* dst, const uint8_t* src, uint32_t n);
uint32_t vm_checksum(const uint8_t* p, uint32_t n);
uint32_t vm_mix32(uint32_t x);
uint32_t vm_serial_for(const char* name, uint32_t len);

static const uint8_t MSGC[49] = {0xf7,0xc2,0xf0,0xc4,0x32,0x4e,0xba,0x5b,0x65,
0x34,0xd1,0xad,0xbf,0x45,0x1b,0x24,0x68,0xf7,0xd4,0x86,0xf1,0x5d,0x35,0x75,
0x83,0xab,0x30,0x01,0x55,0x4b,0x48,0xd9,0x2c,0xee,0x55,0x2e,0x26,0x07,0x28,
0x60,0x29,0x89,0x56,0x2d,0x84,0xb3,0x07,0x16,0x7d};

int main(void) {
  uint8_t out[50];
  uint32_t acc;
  uint32_t c;
  acc = vm_decode_msg(out, MSGC, 49);
  out[49] = 0;
  puts((const char*)out);
  c = vm_checksum(MSGC, 49);
  printf("chk=%08x mix=%08x\n", c, vm_mix32(c ^ acc));
  printf("serial=%08x\n", vm_serial_for((const char*)out + 34, 13));
  printf("serial2=%08x\n", vm_serial_for((const char*)out, 17));
  return 0;
}
