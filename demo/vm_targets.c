/* Demo targets: the "real" algorithmic core of a fictional license-check /
 * codec app. These four functions get virtualized; everything else in the
 * program stays native. */
uint32_t vm_decode_msg(uint8_t* dst, const uint8_t* src, uint32_t n) {
  uint32_t k; uint32_t i; uint32_t acc;
  k = 0x5A17C34Bu;
  acc = 0;
  for (i = 0; i < n; i = i + 1) {
    k = k * 1103515245u + 12345u;
    dst[i] = (uint8_t)(src[i] ^ (uint8_t)((k >> 16) ^ (i * 3u)));
    acc = acc + (uint32_t)dst[i];
  }
  return acc;
}

uint32_t vm_checksum(const uint8_t* p, uint32_t n) {
  uint32_t h; uint32_t i;
  h = 0xC0FFEE11u;
  for (i = 0; i < n; i = i + 1) {
    h = (h << 7) | (h >> 25);
    h = h ^ (p[i] * 0x1B87359Bu + i);
  }
  return h;
}

uint32_t vm_mix32(uint32_t x) {
  x = x ^ (x >> 16);
  x = x * 0x85EBCA6Bu;
  x = x ^ (x >> 13);
  x = x * 0xC2B2AE35u;
  x = x ^ (x >> 16);
  return x;
}

uint32_t vm_serial_for(const char* name, uint32_t len) {
  uint32_t h; uint32_t i;
  h = 0x9E3779B9u ^ (len * 4u);
  for (i = 0; i < len; i = i + 1) {
    h = h + ((uint32_t)name[i] * (i + 7u));
    h = (h << 5) | (h >> 27);
    h = h ^ (h >> 3);
  }
  h = h ^ 0x85EBCA6Bu;
  return h;
}
