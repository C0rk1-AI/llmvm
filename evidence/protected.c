/* auto-generated - do not edit */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

#define NFR 64
#define VSTK 256

typedef struct _vmst {
    const unsigned char *bc; uint32_t pc; uint32_t pp; uint32_t lp;
    uint64_t st[VSTK]; int sp; uint64_t fr[NFR]; int alive;
} vmst;

typedef void (*vmhf)(vmst *);

static uint32_t G_k1, G_k2, G_k3;
static uint32_t G_b1, G_b2, G_b3;   /* base keys: every function's entry state */
static uint64_t G_mk;
static uintptr_t G_t[256];
static uintptr_t G_host[4];
static unsigned char G_harn[4];
struct vme { uintptr_t bcp; uint32_t n; unsigned char na; };
static struct vme G_vmt[4];
static unsigned char *G_db[1];

static uint32_t rotl(uint32_t v, unsigned r){
    r &= 31u; if (!r) return v; return (v << r) | (v >> (32u - r));
}
static void vm_exec_core(const unsigned char *bc, uint32_t n,
                         unsigned char na, uint64_t *rv);

static uint64_t jn0(void){
    volatile uint64_t q = 0xbc0350682887d3aaull;
    q ^= q >> 13; q *= 0x2545F4914F6CDD1Dull; q ^= q >> 27;
    return q;
}
static uint64_t jn1(void){
    volatile uint64_t q = 0x0e48681cf2a7845eull;
    q ^= q >> 13; q *= 0x2545F4914F6CDD1Dull; q ^= q >> 27;
    return q;
}
static uint64_t jn2(void){
    volatile uint64_t q = 0x1a40ec41fb22532bull;
    q ^= q >> 13; q *= 0x2545F4914F6CDD1Dull; q ^= q >> 27;
    return q;
}
static uint64_t jn3(void){
    volatile uint64_t q = 0x2c66e567a45ba5d3ull;
    q ^= q >> 13; q *= 0x2545F4914F6CDD1Dull; q ^= q >> 27;
    return q;
}
static const uint32_t T_bmp[10] = {0x00004d42u,0x00000036u,0x00000110u,0x00000028u,0x00000040u,0x00000040u,0x00000001u,0x00000018u,0x00000000u,0x00000f00u};
static const unsigned char T_rle[16] = {0x00,0x05,0x12,0x00,0x00,0xff,0x03,0x41,0x42,0x43,0x00,0x00,0x02,0x7f,0x00,0x02};
static const uint32_t T_cos[12] = {0x2d41u,0x3b21u,0x2d41u,0x187eu,0x2d41u,0x0c7eu,0x2d41u,0x064eu,0x3b21u,0x2d41u,0x3b21u,0x0c7eu};
static const unsigned char T_huf[24] = {0x1f,0x00,0x11,0x2f,0x5d,0x01,0x00,0x03,0x84,0x1b,0x77,0x00,0x0a,0xc4,0x1e,0x2d,0x00,0x09,0x5b,0x31,0x62,0x00,0x00,0x48};
static const uint32_t T_md5[8] = {0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u};
static const unsigned char T_qmt[64] = {16,11,10,16,24,40,51,61,12,12,14,19,26,58,60,55,14,13,16,24,40,57,69,56,14,17,22,29,51,87,80,62,18,22,37,56,68,109,103,77,24,35,55,64,81,104,113,92,49,64,78,87,103,121,120,101,72,92,95,98,112,100,103,99};
static const uint32_t T_crc[256] = {0x00000000u,0x77073096u,0xee0e612cu,0x990951bau,0x076dc419u,0x706af48fu,0xe963a535u,0x9e6495a3u,0x0edb8832u,0x79dcb8a4u,0xe0d5e91eu,0x97d2d988u,0x09b64c2bu,0x7eb17cbdu,0xe7b82d07u,0x90bf1d91u,0x1db71064u,0x6ab020f2u,0xf3b97148u,0x84be41deu,0x1adad47du,0x6ddde4ebu,0xf4d4b551u,0x83d385c7u,0x136c9856u,0x646ba8c0u,0xfd62f97au,0x8a65c9ecu,0x14015c4fu,0x63066cd9u,0xfa0f3d63u,0x8d080df5u,0x3b6e20c8u,0x4c69105eu,0xd56041e4u,0xa2677172u,0x3c03e4d1u,0x4b04d447u,0xd20d85fdu,0xa50ab56bu,0x35b5a8fau,0x42b2986cu,0xdbbbc9d6u,0xacbcf940u,0x32d86ce3u,0x45df5c75u,0xdcd60dcfu,0xabd13d59u,0x26d930acu,0x51de003au,0xc8d75180u,0xbfd06116u,0x21b4f4b5u,0x56b3c423u,0xcfba9599u,0xb8bda50fu,0x2802b89eu,0x5f058808u,0xc60cd9b2u,0xb10be924u,0x2f6f7c87u,0x58684c11u,0xc1611dabu,0xb6662d3du,0x76dc4190u,0x01db7106u,0x98d220bcu,0xefd5102au,0x71b18589u,0x06b6b51fu,0x9fbfe4a5u,0xe8b8d433u,0x7807c9a2u,0x0f00f934u,0x9609a88eu,0xe10e9818u,0x7f6a0dbbu,0x086d3d2du,0x91646c97u,0xe6635c01u,0x6b6b51f4u,0x1c6c6162u,0x856530d8u,0xf262004eu,0x6c0695edu,0x1b01a57bu,0x8208f4c1u,0xf50fc457u,0x65b0d9c6u,0x12b7e950u,0x8bbeb8eau,0xfcb9887cu,0x62dd1ddfu,0x15da2d49u,0x8cd37cf3u,0xfbd44c65u,0x4db26158u,0x3ab551ceu,0xa3bc0074u,0xd4bb30e2u,0x4adfa541u,0x3dd895d7u,0xa4d1c46du,0xd3d6f4fbu,0x4369e96au,0x346ed9fcu,0xad678846u,0xda60b8d0u,0x44042d73u,0x33031de5u,0xaa0a4c5fu,0xdd0d7cc9u,0x5005713cu,0x270241aau,0xbe0b1010u,0xc90c2086u,0x5768b525u,0x206f85b3u,0xb966d409u,0xce61e49fu,0x5edef90eu,0x29d9c998u,0xb0d09822u,0xc7d7a8b4u,0x59b33d17u,0x2eb40d81u,0xb7bd5c3bu,0xc0ba6cadu,0xedb88320u,0x9abfb3b6u,0x03b6e20cu,0x74b1d29au,0xead54739u,0x9dd277afu,0x04db2615u,0x73dc1683u,0xe3630b12u,0x94643b84u,0x0d6d6a3eu,0x7a6a5aa8u,0xe40ecf0bu,0x9309ff9du,0x0a00ae27u,0x7d079eb1u,0xf00f9344u,0x8708a3d2u,0x1e01f268u,0x6906c2feu,0xf762575du,0x806567cbu,0x196c3671u,0x6e6b06e7u,0xfed41b76u,0x89d32be0u,0x10da7a5au,0x67dd4accu,0xf9b9df6fu,0x8ebeeff9u,0x17b7be43u,0x60b08ed5u,0xd6d6a3e8u,0xa1d1937eu,0x38d8c2c4u,0x4fdff252u,0xd1bb67f1u,0xa6bc5767u,0x3fb506ddu,0x48b2364bu,0xd80d2bdau,0xaf0a1b4cu,0x36034af6u,0x41047a60u,0xdf60efc3u,0xa867df55u,0x316e8eefu,0x4669be79u,0xcb61b38cu,0xbc66831au,0x256fd2a0u,0x5268e236u,0xcc0c7795u,0xbb0b4703u,0x220216b9u,0x5505262fu,0xc5ba3bbeu,0xb2bd0b28u,0x2bb45a92u,0x5cb36a04u,0xc2d7ffa7u,0xb5d0cf31u,0x2cd99e8bu,0x5bdeae1du,0x9b64c2b0u,0xec63f226u,0x756aa39cu,0x026d930au,0x9c0906a9u,0xeb0e363fu,0x72076785u,0x05005713u,0x95bf4a82u,0xe2b87a14u,0x7bb12baeu,0x0cb61b38u,0x92d28e9bu,0xe5d5be0du,0x7cdcefb7u,0x0bdbdf21u,0x86d3d2d4u,0xf1d4e242u,0x68ddb3f8u,0x1fda836eu,0x81be16cdu,0xf6b9265bu,0x6fb077e1u,0x18b74777u,0x88085ae6u,0xff0f6a70u,0x66063bcau,0x11010b5cu,0x8f659effu,0xf862ae69u,0x616bffd3u,0x166ccf45u,0xa00ae278u,0xd70dd2eeu,0x4e048354u,0x3903b3c2u,0xa7672661u,0xd06016f7u,0x4969474du,0x3e6e77dbu,0xaed16a4au,0xd9d65adcu,0x40df0b66u,0x37d83bf0u,0xa9bcae53u,0xdebb9ec5u,0x47b2cf7fu,0x30b5ffe9u,0xbdbdf21cu,0xcabac28au,0x53b39330u,0x24b4a3a6u,0xbad03605u,0xcdd70693u,0x54de5729u,0x23d967bfu,0xb3667a2eu,0xc4614ab8u,0x5d681b02u,0x2a6f2b94u,0xb40bbe37u,0xc30c8ea1u,0x5a05df1bu,0x2d02ef8du};

uint32_t dec_md5_mix(void){
    uint32_t m = 0x67452301u, b; unsigned i;
    for (i = 0; i < 8; i++) { b = 0xEFCDAB89u + T_md5[i]; m = rotl(m ^ b, 7u) + T_md5[i] + (uint32_t)i; }
    return m;
}
uint32_t dec_huff_walk(void){
    uint32_t w = 0x0000ABCDu; unsigned i;
    for (i = 0; i < 24; i++) {
        if (T_huf[i]) w = rotl(w, T_huf[i] & 7u) + T_huf[i];
        else w ^= 0x61C88647u;
    }
    return w;
}
uint32_t dec_bmp_probe(void){
    uint32_t h = 0x4D42u; unsigned i;
    for (i = 0; i < 10; i++) h = rotl(h ^ T_bmp[i], (i & 7u) + 1u) + 0x4009u;
    return h ^ 0x1Fu;
}
uint32_t dec_rle_scan(void){
    uint32_t r = 0x00FF00FFu; unsigned i;
    for (i = 0; i < 16; i++) {
        if (T_rle[i] == 0xFFu) r += T_rle[i] * (uint32_t)(i + 3u);
        else r ^= (T_rle[i] + (uint32_t)i) * 0x9D2C5680u;
    }
    return r;
}
uint32_t dec_jpeg_idct(void){
    uint32_t q = 0x00800000u; unsigned i;
    for (i = 0; i < 12; i++) q = (q >> 3) + T_cos[i] * (uint32_t)(i + 1u) + rotl(q, i & 15u);
    return q;
}
uint32_t dec_png_crc(void){
    uint32_t c = 0xFFFFFFFFu; static const unsigned char P[16] =
        {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}; unsigned i;
    for (i = 0; i < 16; i++) c = (c >> 8) ^ T_crc[(c ^ P[i]) & 0xFFu];
    return c ^ 0xFFFFFFFFu;
}
uint32_t dec_quant_check(void){
    uint32_t s = 0u; unsigned i;
    for (i = 0; i < 64; i++) s += T_qmt[i] * (uint32_t)(i + 1u);
    return (s & 0xFFFFu) ^ (rotl(s & 0xFFFFu, 11u) + 0x2C1Bu);
}
static int opq_f(unsigned t){ return (int)(((t * (t + 1u)) & 1u) != 0u); }

static const unsigned char BC0[442] = {
0x3e,0x22,0xc7,0xe1,0x9e,0x24,0xaa,0xde,0x16,0x91,0xd8,0x2c,0x18,0x98,0x79,0xdc,
0xc6,0xb9,0xb2,0xa5,0x4b,0x1f,0x20,0xb8,0x02,0x21,0x0d,0xc0,0x51,0xd5,0xa1,0x89,
0x87,0x33,0xc3,0x5a,0x0b,0xd5,0xf5,0x35,0xf1,0xf6,0x2f,0x7a,0x86,0x42,0x92,0x6d,
0x97,0xc2,0xdf,0x09,0x4d,0x08,0x28,0xe7,0x33,0x2b,0x39,0x71,0xb2,0x5a,0x74,0x1a,
0x7c,0xba,0x8e,0x30,0xd0,0x1f,0x2f,0x9c,0xa0,0xff,0x2a,0xe6,0x18,0x5d,0x80,0x76,
0x5f,0x72,0x05,0xad,0x72,0xbe,0x72,0x48,0x78,0x33,0x23,0xba,0x21,0x44,0xb9,0xff,
0x49,0x0b,0x6b,0x84,0x67,0x34,0x5a,0x2f,0xc1,0x7b,0x71,0x8a,0x5b,0x85,0xf9,0xe6,
0x07,0x47,0x32,0x0c,0x7f,0xf4,0x91,0xb9,0xa4,0xbe,0x8b,0x2d,0x1d,0xe0,0x5e,0x7b,
0x3d,0x97,0xca,0x7d,0x20,0xff,0x13,0x54,0x13,0xba,0x86,0xa9,0xde,0x31,0x53,0x3b,
0xcf,0x96,0xc5,0x04,0x9e,0x35,0xb3,0x2d,0x7b,0xc9,0x0e,0x98,0x43,0x36,0xd6,0x00,
0x41,0x16,0x10,0x58,0xb1,0xc6,0xbf,0x9f,0x47,0xcb,0xff,0xec,0x70,0xc6,0x3e,0x7a,
0x53,0xd0,0xf5,0xcb,0x5e,0xc2,0xda,0xe7,0xd6,0x1e,0x8e,0x64,0x11,0x8d,0xe5,0x45,
0xce,0xe4,0x9a,0x52,0x4d,0xa9,0x9a,0x0d,0xb6,0xda,0x1f,0x1d,0xe4,0x30,0xfc,0xc6,
0xb8,0x03,0x02,0x34,0xfb,0x93,0x7f,0xbd,0x10,0x4a,0x0a,0x59,0xfd,0xaf,0x3e,0x3f,
0x27,0x43,0x63,0x37,0xfd,0x69,0xb7,0xc3,0x96,0x55,0x80,0x3f,0x9f,0x3a,0x4d,0x91,
0xd3,0x26,0x38,0xf0,0x89,0xd4,0xb0,0xbd,0x27,0xc0,0x30,0xf0,0x0a,0x7e,0xd2,0xcb,
0xc2,0xb6,0xd8,0x65,0x76,0x5c,0x9d,0x73,0x5a,0x3a,0xc8,0xdb,0x41,0x38,0x75,0x02,
0x4e,0xcf,0x58,0x79,0x0c,0x34,0xac,0x83,0x79,0x06,0x4f,0x7a,0xe4,0xd5,0x44,0x99,
0x96,0xb5,0x54,0x9c,0xd3,0x9c,0x60,0xa4,0xba,0x07,0xf6,0xf5,0x75,0xfc,0x55,0xf5,
0x87,0x9f,0xfc,0xac,0x18,0x45,0x9b,0x81,0xb7,0x9e,0xb4,0xf8,0xf4,0x30,0x81,0x15,
0x24,0xf8,0x21,0x13,0x7e,0xc1,0xa3,0x66,0x4a,0xd2,0xf1,0x8e,0x84,0x8a,0x25,0xa0,
0xbf,0x95,0x9c,0x82,0xa9,0x22,0x95,0x34,0xc9,0x8b,0x90,0x91,0xb6,0x2e,0x8c,0x49,
0xb3,0x55,0xeb,0x96,0xaa,0xd5,0x37,0x5f,0xa2,0x94,0x15,0x61,0x7e,0xe9,0x01,0x97,
0x93,0x6c,0x1c,0xde,0xfb,0x13,0xdf,0x79,0xb1,0x73,0xdb,0x96,0x13,0x1c,0x70,0xe6,
0x6a,0x09,0x33,0x68,0x33,0xad,0x41,0x1f,0xb9,0x83,0x43,0x24,0x95,0x09,0x8d,0x0b,
0x03,0xe4,0x8e,0xb7,0xd6,0xcc,0xca,0x03,0xd1,0x41,0xda,0x94,0xc1,0xdf,0x0e,0x1b,
0x98,0x8e,0x86,0x6e,0x6c,0x86,0xf6,0x1d,0xf5,0xe1,0x45,0x0f,0xb1,0xba,0x5d,0x80,
0xdc,0x82,0x37,0x31,0x6d,0xfd,0x6c,0xdf,0x85,0x30
};
static const unsigned char BC1[259] = {
0x57,0xe8,0xca,0x21,0xdb,0xb7,0x59,0x55,0xb8,0xf8,0x50,0xfe,0x00,0x3e,0x0c,0xe0,
0x3d,0x2e,0x27,0x29,0xce,0x0d,0x3e,0xd0,0xda,0xb9,0xf5,0xee,0x25,0x8b,0x36,0xa1,
0xf7,0xef,0x7d,0xfe,0xc6,0x48,0x71,0xab,0x37,0xcd,0xcb,0x34,0xab,0xeb,0x6f,0x28,
0x08,0xba,0x31,0xcf,0xe0,0x12,0xd1,0x5a,0x63,0xd3,0xe6,0x6f,0x38,0xd8,0x36,0xde,
0x02,0xc7,0x08,0x29,0xc0,0x7e,0x48,0x2d,0x4c,0x24,0xcc,0xab,0x85,0xf7,0xcf,0x10,
0x12,0x62,0x75,0x19,0x9b,0xa3,0x66,0x31,0x35,0x7d,0x8b,0xa7,0x49,0x3b,0xe2,0xa3,
0x27,0xf8,0xc1,0x2f,0xeb,0x4f,0xcd,0x1a,0x04,0x19,0x3d,0x43,0xfd,0x4f,0xfe,0xe2,
0x97,0xa3,0x8b,0xb0,0x4e,0xea,0xe5,0x52,0xb1,0xdd,0x8d,0xac,0x51,0xf2,0x37,0xbd,
0x40,0xde,0x35,0xd4,0x0b,0xee,0xf5,0x76,0xf3,0xbb,0xda,0x72,0xf4,0x9c,0xe3,0xb2,
0xe9,0x88,0xd6,0xf5,0x4e,0xae,0x0b,0xd4,0xe3,0xe5,0xec,0x17,0x67,0x45,0xbf,0x83,
0x83,0x73,0xd1,0xad,0x2c,0x18,0xa5,0x62,0x4f,0x86,0xb2,0x96,0x4a,0x82,0x45,0x04,
0x66,0x65,0x7a,0x7f,0xa7,0xce,0x99,0xcd,0x43,0xd4,0x05,0x0b,0xa7,0xf6,0x42,0xb2,
0x70,0xf5,0x43,0xf4,0x18,0xcd,0x53,0x6f,0x8a,0x9b,0x56,0x24,0xc8,0x92,0x6d,0x5a,
0x60,0x4a,0x36,0x29,0xb7,0xc9,0x3e,0x8d,0x66,0xbf,0x5b,0xb0,0x1c,0xdd,0xc8,0x0b,
0x91,0xdc,0xca,0xb3,0x07,0xb4,0x1f,0x02,0x4f,0xfe,0x2c,0xd4,0xc2,0x26,0x07,0xc0,
0x99,0xa0,0xfc,0xf7,0xb2,0xb5,0xfa,0x13,0xc5,0xf5,0x8e,0x50,0xa0,0x23,0x70,0x21,
0xed,0xf8,0xb1
};
static const unsigned char BC2[176] = {
0x57,0x30,0xee,0xd1,0xcd,0x2c,0xab,0xb1,0x16,0x91,0x30,0xcb,0x42,0x3c,0xaf,0x73,
0x1f,0x7c,0x07,0xa5,0x7c,0x18,0x1e,0xa5,0xc8,0x6a,0x19,0x75,0xc8,0xf1,0x77,0xd3,
0xf0,0xa5,0x6b,0x84,0x42,0x87,0xb0,0x1a,0xfb,0x80,0xb3,0x17,0xdb,0x6e,0x30,0x5d,
0xf1,0x61,0x5c,0x90,0xb3,0x3d,0x11,0x0e,0x7f,0x15,0xd4,0xe5,0x56,0x4c,0x0d,0x91,
0x90,0x25,0x00,0xb0,0x15,0xd1,0xd4,0x08,0x6e,0x8d,0x52,0x55,0x04,0x7a,0xa7,0x4a,
0xad,0x2e,0xf7,0xbd,0xdc,0x65,0x47,0xae,0x59,0x8d,0x53,0x94,0x3c,0xef,0x69,0x19,
0xeb,0x75,0x42,0x4d,0x21,0xce,0xcd,0x45,0xb8,0xc2,0xb1,0x0c,0x8a,0x46,0x06,0xec,
0x5f,0xbc,0x6e,0xcf,0x0e,0x42,0x52,0x37,0x63,0x3e,0x05,0x40,0x2b,0x06,0xd5,0xc7,
0xf1,0xc0,0x3b,0x9f,0x97,0xbd,0x06,0x22,0x86,0x3d,0x05,0x10,0x95,0x33,0x9d,0xd4,
0xfd,0x78,0x4e,0x4d,0x06,0xd7,0xdb,0xf4,0x47,0xdf,0x1e,0x9d,0x43,0x0a,0xb0,0xa9,
0xa5,0xc7,0x9f,0xfb,0xda,0x6a,0x5d,0x09,0xd5,0x3a,0x75,0xe1,0xda,0x39,0x13,0x52
};
static const unsigned char BC3[324] = {
0x57,0xe4,0x68,0xec,0x60,0x09,0xa9,0x2e,0x9a,0xf8,0x1b,0x84,0x21,0xfe,0x28,0x06,
0x30,0x65,0xb8,0x0d,0xa8,0xfb,0xa8,0xc3,0xe6,0x52,0xb3,0xa8,0xc8,0xd5,0xdb,0x64,
0x46,0x97,0x00,0x72,0xf9,0x09,0xa0,0xd0,0x09,0x35,0xf8,0x2f,0x5c,0xa4,0x03,0xb7,
0x09,0x7f,0x5f,0x39,0xf2,0x5d,0x23,0x44,0x8c,0xe7,0x21,0x0f,0x23,0x50,0xc0,0xfb,
0xb1,0xb5,0x66,0xff,0xb9,0xea,0x19,0x95,0xb7,0xcd,0xde,0xdd,0xb9,0x82,0x12,0x0d,
0xd7,0xec,0xfa,0x79,0x6f,0x15,0xad,0x8c,0xb4,0x06,0x3a,0x38,0xf5,0x05,0x94,0x61,
0x16,0x62,0x82,0x3c,0xa1,0x74,0x3a,0x1c,0x85,0xf1,0xea,0x0c,0xff,0x2c,0x61,0x69,
0x6a,0x36,0x50,0x82,0xfe,0xc7,0xd3,0x69,0xbb,0xe9,0xe3,0xca,0x94,0xbf,0x6f,0x81,
0x07,0x22,0xa0,0x3f,0x62,0x93,0xd8,0xe9,0x66,0x16,0x4e,0xf0,0xdc,0x8a,0xc3,0x08,
0x70,0x89,0x14,0x32,0x01,0xf3,0x1f,0xf2,0xf3,0x69,0x7a,0x41,0x82,0xb6,0x16,0x9f,
0xdc,0x83,0x24,0x49,0x98,0xbf,0x10,0xf6,0xd1,0x22,0x17,0x47,0xf6,0x51,0x9a,0x05,
0xd2,0x3f,0x7c,0xd1,0x68,0xbf,0x4e,0x52,0x5d,0x9c,0x76,0xad,0xb3,0x50,0x70,0x0c,
0xd1,0x99,0x76,0x31,0x69,0x73,0xb1,0x49,0x94,0xad,0xb6,0x7f,0x8a,0x98,0x47,0xdb,
0x08,0xa1,0xcb,0x1f,0xa4,0x17,0xb3,0x8f,0x4c,0x01,0xd3,0x39,0x13,0x38,0x3d,0xbf,
0x49,0xf4,0x04,0x26,0xab,0x9c,0x4e,0x98,0x28,0xd3,0x51,0x11,0xcc,0xf7,0x06,0x91,
0xb5,0x2d,0xe8,0x0b,0xbd,0x6c,0x87,0x41,0x72,0x11,0x84,0xb9,0x21,0x1d,0x80,0xd6,
0x0b,0xc6,0x01,0x6d,0x50,0x64,0xef,0xd5,0x5a,0xf8,0x7d,0x34,0x0e,0x93,0xed,0x92,
0xb7,0x32,0xab,0xf3,0x05,0x88,0x44,0xcf,0x4e,0x72,0xa0,0x19,0x05,0x0e,0x4f,0x8a,
0x25,0x9b,0x2c,0x62,0xd5,0x74,0xdf,0x16,0xa3,0x2b,0x32,0xf8,0x47,0x51,0xaa,0x17,
0xfb,0x3e,0xb2,0xb1,0xc6,0x25,0x3b,0xe0,0x01,0x30,0xae,0xf4,0xbf,0xea,0x76,0x6c,
0x96,0x4c,0xad,0x5b
};
static uint32_t km(uint32_t x){
    x ^= x >> 11u; x *= 0x85ebca6bu; x ^= x >> 15u; x *= 0xc2b2ae35u; return x ^ (x >> 17u);
}
static uint32_t km2(uint32_t x){
    uint32_t h = x ^ (x >> 11u);
    h = (h << 31u) + h * 0x05ebca6bu;
    h ^= h >> 15u;
    h = (h << 31u) + h * 0x42b2ae35u;
    return h ^ (h >> 17u);
}
static unsigned char dmx(unsigned int p){
    return (unsigned char)(km2(0x2dfb849cu ^ (p * 0x85ebca77u + 39u)) >> 13u);
}
static unsigned char nxb0(vmst *s){
    unsigned int p = s->pc;
    uint32_t t3 = km(((G_k3 + (rotl(p, 5u))) - ((G_k3 & (rotl(p, 5u))) << 1u)));
    uint32_t w1 = km2(G_k1 ^ ((p * 0x9e3779b1u)));
    uint32_t t2 = km2(G_k2 + (p));
    unsigned char cx = (unsigned char)(s->bc[p] ^ (unsigned char)((((w1 ^ (t2 + t3)) >> 16u) & 0xFFu)));
    s->pc++; s->pp++; s->lp = p;
    return cx;
}
static uint32_t w0(vmst *s){uint32_t r = 0; r |= (uint32_t)nxb0(s); r |= (uint32_t)nxb0(s) << 8; r |= (uint32_t)nxb0(s) << 16; r |= (uint32_t)nxb0(s) << 24; return r; }
static uint64_t w0_q(vmst *s){uint64_t r = 0; int i; for (i = 0; i < 8; i++) r |= (uint64_t)nxb0(s) << (8 * i); return r; }
static unsigned char nxb1(vmst *s){
    unsigned int p = s->pc;
    uint32_t t3 = km2(G_k1 ^ ((p * 0x9e3779b1u)));
    uint32_t w1 = km2((G_k2 ^ (p)) + ((G_k2 & (p)) << 1u));
    uint32_t u3 = km(((G_k3 + (rotl(p, 5u))) - ((G_k3 & (rotl(p, 5u))) << 1u)));
    unsigned char b9 = (unsigned char)(s->bc[p] ^ (unsigned char)((((t3 ^ (w1 + u3)) >> 16u) & 0xFFu)));
    s->pc++; s->pp++; s->lp = p;
    return b9;
}
static uint32_t w1(vmst *s){uint32_t r = 0; r |= (uint32_t)nxb1(s); r |= (uint32_t)nxb1(s) << 8; r |= (uint32_t)nxb1(s) << 16; r |= (uint32_t)nxb1(s) << 24; return r; }
static uint64_t w1_q(vmst *s){uint64_t r = 0; int i; for (i = 0; i < 8; i++) r |= (uint64_t)nxb1(s) << (8 * i); return r; }
static unsigned char nxb2(vmst *s){
    unsigned int p = s->pc;
    uint32_t u2 = km2(G_k2 + (p));
    uint32_t w2 = km(G_k1 ^ (p * 0x9e3779b1u));
    uint32_t t3 = km(((G_k3 + (rotl(p, 5u))) - ((G_k3 & (rotl(p, 5u))) << 1u)));
    unsigned char ob = (unsigned char)(s->bc[p] ^ (unsigned char)(((((u2 + t3) ^ w2) >> 16u) & 0xFFu)));
    s->pc++; s->pp++; s->lp = p;
    return ob;
}
static uint32_t w2(vmst *s){uint32_t r = 0; r |= (uint32_t)nxb2(s); r |= (uint32_t)nxb2(s) << 8; r |= (uint32_t)nxb2(s) << 16; r |= (uint32_t)nxb2(s) << 24; return r; }
static uint64_t w2_q(vmst *s){uint64_t r = 0; int i; for (i = 0; i < 8; i++) r |= (uint64_t)nxb2(s) << (8 * i); return r; }
static unsigned char nxb3(vmst *s){
    unsigned int p = s->pc;
    uint32_t w1 = km2(((G_k3 + (rotl(p, 5u))) - ((G_k3 & (rotl(p, 5u))) << 1u)));
    uint32_t t3 = km2(G_k1 ^ ((p * 0x9e3779b1u)));
    uint32_t u3 = km(G_k2 + (p));
    unsigned char ob = (unsigned char)(s->bc[p] ^ (unsigned char)((unsigned char)(((u3 + w1) ^ t3) >> 16u)));
    s->pc++; s->pp++; s->lp = p;
    return ob;
}
static uint32_t w3(vmst *s){uint32_t r = 0; r |= (uint32_t)nxb3(s); r |= (uint32_t)nxb3(s) << 8; r |= (uint32_t)nxb3(s) << 16; r |= (uint32_t)nxb3(s) << 24; return r; }
static uint64_t w3_q(vmst *s){uint64_t r = 0; int i; for (i = 0; i < 8; i++) r |= (uint64_t)nxb3(s) << (8 * i); return r; }

/* ---- inner VM (V3-a): outer fetch/flow/rekey ops live here as data ---- */
typedef struct _imst {
    const unsigned char *ip; uint32_t pc; uint64_t v[8]; int sp;
    uint64_t scr; uint64_t jj; int alive;
} imst;
typedef void (*imhf)(imst *, vmst *);
static uint32_t G_i1, G_i2, G_i3;
static uint64_t G_imk;
static uintptr_t G_it[256];
static uint32_t ikm(uint32_t x){
    x ^= x >> 12u; x *= 0x27220a95u; x ^= x >> 15u; x *= 0x2545f491u; return x ^ (x >> 13u);
}
static uint32_t ikm2(uint32_t x){
    uint32_t h = x ^ (x >> 12u);
    h = (h << 29u) + h * 0x07220a95u;
    h ^= h >> 15u;
    h = (h << 29u) + h * 0x0545f491u;
    return h ^ (h >> 13u);
}
static unsigned char IMB(imst *m){
    unsigned int p = m->pc;
    uint32_t w2 = ikm2(G_i1 ^ ((p * 0x9e3779b1u)));
    uint32_t w1 = ikm2(((G_i3 + (((p << 11u) | (p >> 21u)))) - ((G_i3 & (((p << 11u) | (p >> 21u)))) << 1u)));
    uint32_t t3 = ikm2(((G_i2 + (p)) - ((G_i2 & (p)) << 1u)));
    unsigned char rb = (unsigned char)(m->ip[p] ^ (unsigned char)(((((w2 ^ t3) ^ w1) >> 16u) & 0xFFu)));
    m->pc++;
    return rb;
}

static uint64_t IMB64(imst *m){
    uint64_t r = 0; int i;
    for (i = 0; i < 8; i++) r |= (uint64_t)IMB(m) << (8 * i);
    return r;
}
static int32_t IMB16S(imst *m){
    uint32_t r = 0; int i;
    for (i = 0; i < 2; i++) r |= (uint32_t)IMB(m) << (8 * i);
    return (int32_t)(int16_t)(uint16_t)r;
}

static void g_ab95(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp++] = IMB64(m);
    m->jj ^= 0x7ea77e36a489ff34ull;
}
static void g_b86a(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp++] = IMB64(m);
    m->jj ^= 0x21d07fe515c60e83ull;
}
static void g_abf4(imst *m, vmst *s){ (void)m; (void)s;
    m->sp--;
    m->jj += (uint64_t)m->pc * 68ull;
}
static void g_2dc1(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp] = m->v[m->sp - 1]; m->sp++;
    m->jj ^= 0x0920169b49eea046ull;
}
static void g_ce9c(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp] = m->v[m->sp - 1]; m->sp++;
    if ((m->pc ^ G_i1) == 0x2f05a30eu) { m->jj ^= 0xcce3f674be7bf827ull; }
}
static void g_2a22(imst *m, vmst *s){ (void)m; (void)s;
    uint64_t e = m->v[m->sp - 1]; m->v[m->sp - 1] = m->v[m->sp - 2]; m->v[m->sp - 2] = e;
    m->jj += (uint64_t)m->pc * 10ull;
}
static void g_810f(imst *m, vmst *s){ (void)m; (void)s;
    uint64_t x = m->v[m->sp - 1]; m->v[m->sp - 1] = m->v[m->sp - 2]; m->v[m->sp - 2] = x;
    m->jj ^= 0x71f4419c5f3f9897ull;
}
static void g_b065(imst *m, vmst *s){ (void)m; (void)s;
    m->scr = m->v[--m->sp];
    if ((m->pc ^ G_i1) == 0x7b468278u) { m->jj ^= 0xdfbca33362884a68ull; }
}
static void g_2be4(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp++] = m->scr;
    m->jj ^= 0xafa3cdfdd0426eeaull;
}
static void g_2e96(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp++] = m->scr;
    if ((m->pc ^ G_i2) == 0xed9b4699u) { m->jj ^= 0x2dd2b82a5d519dd5ull; }
}
static void g_2856(imst *m, vmst *s){ (void)m; (void)s;
    uint64_t e = m->v[--m->sp]; uint64_t y = m->v[--m->sp];
    m->v[m->sp++] = y + e;
    m->jj ^= 0x49e8e1bbac34cc58ull;
}
static void g_a2af(imst *m, vmst *s){ (void)m; (void)s;
    uint64_t b = m->v[--m->sp]; uint64_t y = m->v[--m->sp];
    m->v[m->sp++] = y - b;
    m->jj += (uint64_t)m->pc * 17ull;
}
static void g_e5a0(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp - 2] = m->v[m->sp - 2] * m->v[m->sp - 1]; m->sp--;
    m->jj += (uint64_t)m->pc * 76ull;
}
static void g_e845(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp - 2] = m->v[m->sp - 2] ^ m->v[m->sp - 1]; m->sp--;
    if ((m->pc ^ G_i2) == 0x57d9e90fu) { m->jj ^= 0xa5d8ff832582e843ull; }
}
static void g_b87b(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp - 2] = m->v[m->sp - 2] & m->v[m->sp - 1]; m->sp--;
    m->jj ^= 0xf03f55af5bf04aeaull;
}
static void g_e8fb(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp - 2] = m->v[m->sp - 2] & m->v[m->sp - 1]; m->sp--;
    if ((m->pc ^ G_i1) == 0x12a91e03u) { m->jj ^= 0x82979d134937fd95ull; }
}
static void g_c6d1(imst *m, vmst *s){ (void)m; (void)s;
    uint64_t a = m->v[--m->sp]; uint64_t b = m->v[--m->sp];
    m->v[m->sp++] = b | a;
    m->jj += (uint64_t)m->pc * 68ull;
}
static void g_fbd8(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp - 2] = m->v[m->sp - 2] << (m->v[m->sp - 1] & 63u); m->sp--;
    m->jj ^= 0x2f9d05cdfd315290ull;
}
static void g_db41(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp - 2] = m->v[m->sp - 2] >> (m->v[m->sp - 1] & 63u); m->sp--;
    m->jj += (uint64_t)m->pc * 16ull;
}
static void g_a485(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp - 2] = (uint64_t)((int64_t)m->v[m->sp - 2] >> (m->v[m->sp - 1] & 63u)); m->sp--;
    if ((m->pc ^ G_i2) == 0x6a37d36bu) { m->jj ^= 0xe6fb8933756b9b03ull; }
}
static void g_a9d0(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp - 1] = (uint64_t)(0 - m->v[m->sp - 1]);
    if ((m->pc ^ G_i1) == 0x70bd99a2u) { m->jj ^= 0x51f96a2e3763fd03ull; }
}
static void g_cf08(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp - 1] = ~m->v[m->sp - 1];
    m->jj ^= 0x8b44eb3a9e7028acull;
}
static void g_01f2(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp - 1] = (uint64_t)(m->v[m->sp - 1] == 0);
    m->jj += (uint64_t)m->pc * 87ull;
}
static void g_c4b3(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp - 1] &= 0xFFFFFFFFu;
    if ((m->pc ^ G_i3) == 0x39df3043u) { m->jj ^= 0x06f4d0bad64f5ae9ull; }
}
static void g_2e10(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp - 1] = (uint64_t)(int64_t)(int32_t)(uint32_t)m->v[m->sp - 1];
    if ((m->pc ^ G_i2) == 0xd325fdf6u) { m->jj ^= 0x94aa39f936e862f6ull; }
}
static void g_3008(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp - 1] = (uint64_t)(int64_t)(int32_t)(uint32_t)m->v[m->sp - 1];
    m->jj += (uint64_t)m->pc * 94ull;
}
static void g_d98b(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp - 1] = rotl((uint32_t)m->v[m->sp - 1], IMB(m));
    m->jj += (uint64_t)m->pc * 74ull;
}
static void g_ba23(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp - 1] = rotl((uint32_t)m->v[m->sp - 1], IMB(m));
    if ((m->pc ^ G_i2) == 0x639ac202u) { m->jj ^= 0x7581eeaf56b33a27ull; }
}
static void g_7d39(imst *m, vmst *s){ (void)m; (void)s;
    s->st[s->sp++] = m->v[--m->sp];
    m->jj += (uint64_t)m->pc * 87ull;
}
static void g_73be(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp++] = s->st[--s->sp];
    if ((m->pc ^ G_i2) == 0x7cff3359u) { m->jj ^= 0x94535019c5a78e3bull; }
}
static void g_7e6c(imst *m, vmst *s){ (void)m; (void)s;
    { unsigned char q = (unsigned char)m->v[--m->sp]; m->v[m->sp++] = s->fr[q & 63u]; }
    if ((m->pc ^ G_i1) == 0xdaa169b6u) { m->jj ^= 0xbbb460be4547fe96ull; }
}
static void g_a707(imst *m, vmst *s){ (void)m; (void)s;
    { uint64_t val = m->v[--m->sp]; unsigned char q = (unsigned char)m->v[--m->sp]; s->fr[q & 63u] = val; }
    if ((m->pc ^ G_i2) == 0xae4ab273u) { m->jj ^= 0x6e031174aac0e146ull; }
}
static void g_e7f1(imst *m, vmst *s){ (void)m; (void)s;
    { uint64_t val = m->v[--m->sp]; unsigned char q = (unsigned char)m->v[--m->sp]; s->fr[q & 63u] = val; }
    m->jj ^= 0x5c90421505a07311ull;
}
static void g_5c81(imst *m, vmst *s){ (void)m; (void)s;
    { unsigned char q = (unsigned char)m->v[--m->sp]; m->v[m->sp++] = (uint64_t)(uintptr_t)G_db[q]; }
    m->jj ^= 0x689d90efa30cca89ull;
}
static void g_e652(imst *m, vmst *s){ (void)m; (void)s;
    { unsigned char q = (unsigned char)m->v[--m->sp]; m->v[m->sp++] = (uint64_t)(uintptr_t)G_db[q]; }
    if ((m->pc ^ G_i1) == 0x9e3e7ec2u) { m->jj ^= 0x46788e5600c872ebull; }
}
static void g_3442(imst *m, vmst *s){
    unsigned int p = s->pc;
    uint32_t t2 = km(G_k1 ^ ((p * 0x9e3779b1u)));
    uint32_t t3 = km2(((G_k3 + (rotl(p, 5u))) - ((G_k3 & (rotl(p, 5u))) << 1u)));
    uint32_t w1 = km2(G_k2 + (p));
    unsigned char cx = (unsigned char)(s->bc[p] ^ (unsigned char)(((((w1 + t3) ^ t2) >> 16u) & 0xFFu)));
    s->pc++; s->pp++; s->lp = p;
    m->v[m->sp++] = cx;
}
static void g_493f(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp - 1] ^= (uint64_t)dmx(s->lp);
    m->jj ^= 0x852ad2a3f7cd61d8ull;
}
static void g_e2ed(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp++] = (uint64_t)s->lp;
    m->jj += (uint64_t)m->pc * 4ull;
}
static void g_0d41(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp++] = (uint64_t)s->pc;
    m->jj ^= 0xa14f5ef125015659ull;
}
static void g_7441(imst *m, vmst *s){ (void)m; (void)s;
    s->pc = (uint32_t)m->v[--m->sp];
    if ((m->pc ^ G_i3) == 0xa697481bu) { m->jj ^= 0xe319f13f8c8b3870ull; }
}
static void g_712d(imst *m, vmst *s){ (void)m; (void)s;
    { uint32_t t = (uint32_t)m->v[--m->sp]; if (m->v[--m->sp]) s->pc = t; }
    m->jj ^= 0x34a0faf102c361deull;
}
static void g_b31b(imst *m, vmst *s){ (void)m; (void)s;
    { uint32_t t = (uint32_t)m->v[--m->sp]; if (!m->v[--m->sp]) s->pc = t; }
    m->jj ^= 0x916cb2ef63549536ull;
}
static void g_f9f4(imst *m, vmst *s){ (void)m; (void)s;
    { uint32_t t = (uint32_t)m->v[--m->sp]; if (!m->v[--m->sp]) s->pc = t; }
    m->jj += (uint64_t)m->pc * 88ull;
}
static void g_c303(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp++] = (uint64_t)G_k1;
    if ((m->pc ^ G_i2) == 0x350c10ceu) { m->jj ^= 0x700aa2988180deabull; }
}
static void g_ce17(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp++] = (uint64_t)G_k2;
    m->jj += (uint64_t)m->pc * 67ull;
}
static void g_cfe4(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp++] = (uint64_t)G_k2;
    m->jj ^= 0x1af1650b5528d567ull;
}
static void g_acb5(imst *m, vmst *s){ (void)m; (void)s;
    m->v[m->sp++] = (uint64_t)G_k3;
    m->jj ^= 0x5911f01a9f7ade9bull;
}
static void g_ee01(imst *m, vmst *s){ (void)m; (void)s;
    G_k1 = (uint32_t)m->v[--m->sp];
    m->jj += (uint64_t)m->pc * 42ull;
}
static void g_b55b(imst *m, vmst *s){ (void)m; (void)s;
    G_k1 = (uint32_t)m->v[--m->sp];
    m->jj += (uint64_t)m->pc * 44ull;
}
static void g_924b(imst *m, vmst *s){ (void)m; (void)s;
    G_k2 = (uint32_t)m->v[--m->sp];
    m->jj ^= 0x2e12d08fece6a7edull;
}
static void g_bef9(imst *m, vmst *s){ (void)m; (void)s;
    G_k2 = (uint32_t)m->v[--m->sp];
    m->jj ^= 0x08d7a27c8cb90f53ull;
}
static void g_b13a(imst *m, vmst *s){ (void)m; (void)s;
    G_k3 = (uint32_t)m->v[--m->sp];
    m->jj ^= 0xd0fd2d84b135eef5ull;
}
static void g_8bc8(imst *m, vmst *s){ (void)m; (void)s;
    G_k3 = (uint32_t)m->v[--m->sp];
    m->jj += (uint64_t)m->pc * 86ull;
}
static void g_b4fd(imst *m, vmst *s){ (void)m; (void)s;
    m->pc = (uint32_t)((int32_t)m->pc + IMB16S(m));
    m->jj ^= 0x5b0ecc410dafb78eull;
}
static void g_666f(imst *m, vmst *s){ (void)m; (void)s;
    m->pc = (uint32_t)((int32_t)m->pc + IMB16S(m));
    m->jj ^= 0x62485c5957763e85ull;
}
static void g_1700(imst *m, vmst *s){ (void)m; (void)s;
    { int32_t r = IMB16S(m); if (m->v[--m->sp]) m->pc = (uint32_t)((int32_t)m->pc + r); }
    m->jj += (uint64_t)m->pc * 55ull;
}
static void g_8575(imst *m, vmst *s){ (void)m; (void)s;
    { int32_t r = IMB16S(m); if (!m->v[--m->sp]) m->pc = (uint32_t)((int32_t)m->pc + r); }
    if ((m->pc ^ G_i1) == 0x37abd1b8u) { m->jj ^= 0x17f160b9e271f5c3ull; }
}
static void g_b461(imst *m, vmst *s){ (void)m; (void)s;
    { int32_t r = IMB16S(m); if (!m->v[--m->sp]) m->pc = (uint32_t)((int32_t)m->pc + r); }
    m->jj ^= 0x1949ce8eebfd04eeull;
}
static void g_9a79(imst *m, vmst *s){ (void)m; (void)s;
    m->alive = 0;
    if ((m->pc ^ G_i3) == 0x481c57fau) { m->jj ^= 0xfd95c1f29c2d9f6cull; }
}
static void g_d7b7(imst *m, vmst *s){ (void)m; (void)s;
    m->alive = 0;
    if ((m->pc ^ G_i2) == 0x3345aab3u) { m->jj ^= 0x2f93a759a878567cull; }
}

static void imx_run(const unsigned char *p, vmst *s){
    imst m;
    m.ip = p; m.pc = 0; m.sp = 0; m.scr = 0; m.jj = 0; m.alive = 1;
    while (m.alive) {
        unsigned char op = IMB(&m);
        ((imhf)(G_it[op] ^ (uint64_t)G_imk))(&m, s);
    }
}
static const unsigned char IM0[106] = {
0xa2,0x9c,0x8b,0x12,0x9b,0x75,0xb6,0x72,0xcd,0x3a,0xd1,0xd7,0x02,0xab,0x93,0x4f,
0x24,0xd3,0x2e,0x2f,0x62,0x75,0xa9,0xfd,0x65,0xd0,0x62,0xce,0x68,0x94,0x1f,0xcd,
0x37,0x3f,0x61,0x7d,0xd0,0x3d,0xd7,0x1e,0x9b,0xab,0xc4,0xa9,0x53,0xc9,0x9a,0xa6,
0xf6,0x4f,0xf9,0x4d,0x4e,0xdf,0xc5,0x1b,0x71,0x7e,0x79,0xc0,0xcf,0x07,0x4a,0xb7,
0x4b,0xfc,0xc1,0x1b,0xcc,0x26,0xe2,0xeb,0x99,0xed,0x79,0xf0,0x4b,0xdc,0xd9,0x7d,
0x78,0x94,0xf7,0x88,0x7f,0xa8,0x6b,0xf5,0x5a,0x79,0x0e,0x70,0x05,0x17,0xd6,0x4a,
0xdc,0xa8,0xe1,0xce,0x17,0xcf,0x7c,0x9b,0xae,0x06
};
static const unsigned char IM1[89] = {
0xff,0x47,0x8b,0x12,0x9b,0x75,0xb6,0x72,0xcd,0xeb,0xcb,0x0d,0x02,0xab,0x93,0x4f,
0x24,0xd3,0x2e,0x88,0x7f,0x4a,0xa3,0x26,0x6c,0xd0,0x62,0xce,0x68,0x94,0x1f,0x6a,
0x2a,0x00,0x6b,0xa6,0xc0,0x3c,0xd7,0x1e,0x9b,0xab,0xc4,0x0e,0x4e,0xf6,0x80,0x7d,
0xee,0x4f,0xf8,0x4d,0x4e,0xdf,0xc5,0xbc,0x6c,0xcc,0x4c,0x36,0x7c,0xe5,0x57,0xf0,
0x89,0xfc,0xc1,0x1b,0xcc,0x26,0xe2,0x12,0x75,0xee,0x7c,0x2e,0x0b,0xb9,0xf0,0xbc,
0x57,0x27,0x53,0x29,0xd8,0x8a,0x84,0x52,0x77
};
static const unsigned char IM2[28] = {
0xa8,0x8b,0xe7,0x38,0x40,0xd6,0xb6,0x72,0xcd,0xeb,0x1a,0xd6,0x02,0x52,0x98,0x4f,
0x21,0x18,0xfe,0x2f,0xc6,0xbd,0x73,0xf3,0xd3,0x0d,0xc5,0x5e
};
static const unsigned char IM3[118] = {
0xa2,0x9c,0x8b,0x12,0x9b,0x75,0xb6,0x72,0xcd,0x3a,0xc1,0xd7,0x02,0xab,0x93,0x4f,
0x24,0xd3,0x2e,0x2f,0x62,0x75,0xb9,0xfd,0x65,0xd0,0x62,0xce,0x68,0x94,0x1f,0xcd,
0x37,0x3f,0x61,0x7d,0xd0,0x3d,0xd7,0x1e,0x9b,0xab,0xc4,0xa9,0x53,0xc9,0x8a,0xa6,
0xf6,0x4f,0xf9,0x4d,0x4e,0xdf,0xc5,0x1b,0x71,0xf3,0xaa,0x2e,0x92,0xb8,0x91,0x3a,
0x4b,0xfc,0xc1,0xbc,0x22,0xf7,0x29,0x12,0x8c,0xed,0x7c,0x2b,0xad,0xbc,0x2b,0xe4,
0xba,0x87,0x50,0xab,0x7a,0x0f,0xa0,0x26,0x12,0x12,0x1a,0xcc,0xc3,0x41,0xdf,0x91,
0xc2,0x70,0xe5,0x3b,0xbe,0xe4,0xf8,0x80,0x34,0x49,0xbc,0x9f,0xd3,0x7f,0x15,0x5d,
0xe1,0xda,0x7b,0xcb,0xec,0xe3
};
static const unsigned char IM4[141] = {
0xa2,0x9c,0x8b,0x12,0x9b,0x75,0xb6,0x72,0xcd,0x3a,0xc1,0xd6,0x02,0xab,0x93,0x4f,
0x24,0xd3,0x2e,0x7b,0x89,0x75,0xb9,0xf5,0x64,0xd0,0x62,0xce,0x68,0x94,0x1f,0x99,
0xdc,0x3f,0x71,0x6d,0xd0,0x3c,0xd7,0x1e,0x9b,0xab,0xc4,0xfd,0xb8,0xc9,0x8a,0xbe,
0xf6,0x4f,0xf8,0x4d,0x4e,0xdf,0xc5,0x4f,0x9a,0xf3,0xaa,0x0e,0x92,0xb8,0x91,0x3b,
0x4b,0xfc,0xc1,0xe8,0xc9,0xf7,0x39,0x3a,0x8c,0xed,0x7c,0x2b,0xac,0xbc,0x2b,0xb0,
0x51,0x87,0x50,0x9b,0x7a,0x0f,0xa0,0x26,0x12,0x13,0x1a,0x98,0x28,0x41,0xcf,0xa9,
0xc2,0x70,0xe5,0x3b,0xbe,0xe4,0xf9,0xd4,0xdf,0x49,0xac,0x9d,0x5d,0x7f,0x15,0x5d,
0xe1,0xda,0x7b,0x0f,0x9d,0x73,0x24,0x9a,0xe3,0xea,0x97,0x6e,0x24,0xb8,0x4a,0xb4,
0xd8,0xe2,0x22,0xca,0xb0,0x4b,0xc5,0xe6,0xa8,0xf9,0xf1,0x39,0xbb
};
static const unsigned char IM5[60] = {
0xff,0xfe,0x40,0x32,0x9b,0x75,0xb6,0x72,0xcd,0xeb,0x1a,0x3f,0x7d,0xf6,0xd1,0xe2,
0xca,0xd9,0x7e,0x0d,0x32,0xb6,0x71,0x10,0x34,0x1b,0x09,0x04,0x83,0x11,0x1f,0x6a,
0xd9,0xee,0x1d,0x1c,0x6e,0xd2,0x6d,0xd5,0x14,0xb2,0xd4,0x36,0xbd,0x18,0x51,0xa6,
0x2d,0xea,0xc3,0xd7,0x74,0xdf,0xc5,0xbc,0x9f,0x9c,0x15,0xbe
};
static const unsigned char IM6[31] = {
0xa8,0x8b,0xe7,0x38,0x40,0x11,0x9b,0x72,0xcd,0xeb,0x1a,0xd6,0x02,0x96,0xe7,0x94,
0x25,0xd3,0x2e,0x88,0x8c,0xa4,0x72,0xfd,0x9d,0xd3,0x62,0x3d,0x9b,0x91,0x8f
};
static const unsigned char IM7[96] = {
0xa2,0x8c,0x8b,0x12,0x9b,0x75,0xb6,0x72,0xcd,0x12,0x11,0xd6,0xd9,0x21,0xba,0x3a,
0xda,0x6b,0x54,0xaf,0x8b,0x14,0xc2,0x26,0x64,0xd0,0x62,0xce,0x68,0x94,0x1f,0x6a,
0x08,0x25,0xbb,0x7d,0xd0,0x3c,0xd7,0x1e,0x9b,0xab,0x63,0xe0,0x6c,0xd3,0x51,0xa7,
0xf6,0x4f,0xf8,0x4d,0x4e,0xdf,0x62,0x52,0x4e,0xf9,0x61,0x2e,0x93,0xb8,0x91,0x3b,
0x4b,0xfc,0x66,0xf5,0x1d,0xfd,0xe2,0x12,0x8c,0xec,0x7c,0x2b,0xac,0xbc,0x8c,0xad,
0x08,0x4e,0x65,0xf6,0xc5,0xc4,0xb0,0xca,0xee,0x63,0x16,0x92,0x25,0x02,0x60,0xf4
};
static const unsigned char IM8[72] = {
0xb2,0x49,0x9e,0x03,0x8c,0x75,0xb6,0x72,0xcd,0x20,0x95,0xf0,0x55,0x4c,0x93,0x4f,
0x24,0xd3,0x90,0xfc,0x5d,0xb3,0xf4,0x4c,0xaf,0x05,0x78,0xce,0x68,0x94,0x1f,0x6a,
0xd9,0xd3,0xce,0xb6,0xfc,0x3c,0xd7,0x1e,0x9b,0xab,0xc4,0x0e,0x44,0x15,0x51,0xa3,
0x46,0x4a,0x0b,0x96,0x3c,0x87,0x0c,0x1c,0x86,0x29,0x7f,0x9b,0x59,0x48,0x1f,0x3b,
0x4b,0xfc,0xc1,0x1b,0xcc,0x1b,0x96,0x77
};
static const unsigned char IM9[66] = {
0xb2,0x6e,0xac,0x91,0x02,0x75,0xb6,0x72,0xcd,0x20,0xe7,0x60,0x03,0xf2,0x93,0x4f,
0x24,0xd3,0x90,0xfc,0x5d,0xb3,0x2b,0x36,0x06,0x4f,0xea,0xa9,0x72,0x45,0x10,0x34,
0xad,0x35,0x5c,0xe0,0x91,0xc5,0xd7,0x1e,0x9b,0xab,0x1f,0xdb,0x4e,0x6a,0xaf,0xa6,
0xf6,0x4f,0xf8,0xf3,0x3a,0x14,0x45,0xb8,0x9f,0x22,0x61,0x2e,0x92,0xb8,0xac,0x4f,
0x61,0x6c
};
static const unsigned char IM10[16] = {
0xa8,0x8b,0x0d,0xa3,0x40,0xfe,0x03,0x72,0xcd,0xeb,0x1a,0xd6,0x02,0x96,0xe7,0xdf
};
static const unsigned char IM11[166] = {
0xa2,0xe0,0x1f,0x25,0xa4,0x75,0xb6,0x72,0xcd,0x30,0xcf,0x8e,0xf8,0xf2,0x93,0x4f,
0x24,0xd3,0x90,0xfc,0x47,0xa4,0x72,0xfd,0x64,0xd0,0x62,0xce,0x68,0x45,0xc4,0x6a,
0xd9,0xee,0xba,0x7d,0xd0,0x3c,0xd7,0xed,0x75,0x7a,0x0f,0x06,0xbd,0x18,0x51,0xa6,
0xf6,0x4f,0xf8,0xbe,0xa0,0x0e,0x0e,0xac,0x9f,0x22,0x61,0x2e,0x92,0xb8,0x91,0xc8,
0xa5,0x2d,0x0a,0x03,0xcc,0x26,0xe2,0x12,0x8c,0xed,0x7c,0xd8,0x42,0x6d,0xf0,0x63,
0x54,0x56,0x8b,0xab,0x7a,0x0f,0xa0,0xd5,0xfc,0xc2,0xc1,0x43,0x2d,0x90,0x14,0x91,
0xc2,0x70,0xe5,0xc8,0x50,0x35,0x22,0x17,0xda,0x63,0x67,0xc2,0x5d,0x7f,0x15,0xae,
0x0f,0x0b,0xa0,0xce,0x98,0x73,0xd7,0x9f,0xe6,0x19,0x27,0x46,0x2d,0x92,0x91,0xbc,
0x56,0xf9,0xac,0x63,0x07,0x61,0x6d,0x61,0x90,0xd3,0xf4,0xdf,0x2b,0xab,0xa8,0xaf,
0xf5,0x0a,0xea,0xa3,0xe9,0xce,0x84,0x01,0x85,0x2d,0xfc,0x65,0x5f,0x2e,0x63,0x53,
0x55,0xad,0x98,0x9c,0x67,0x7a
};
static const unsigned char IM12[67] = {
0xb2,0xfc,0xd8,0x12,0x9b,0x75,0xb6,0x72,0xcd,0xd6,0x6e,0x50,0x60,0x60,0xb3,0x4f,
0x24,0xd3,0x2e,0x88,0x8c,0xa4,0x9b,0x82,0x39,0xb2,0xcf,0x20,0x62,0xc4,0x47,0xd4,
0xcb,0xed,0xa4,0xc6,0x0b,0x57,0x1d,0xf5,0x1e,0xab,0xc4,0x0e,0xbd,0xbf,0x30,0x18,
0x18,0x6d,0x33,0x25,0x4e,0xdf,0xc5,0xbc,0x9f,0x22,0x61,0xd7,0x96,0xb8,0x62,0xc8,
0xb8,0x0f,0x51
};
static const unsigned char IM13[84] = {
0xff,0x47,0x8b,0x12,0x9b,0x75,0xb6,0x72,0xcd,0xeb,0xcb,0x1d,0x02,0xab,0x93,0x4f,
0x24,0xd3,0x2e,0x88,0x7f,0x4a,0xa3,0x26,0x6c,0xd0,0x62,0xce,0x68,0x94,0x1f,0x6a,
0x2a,0x00,0x6b,0xa6,0xc0,0x3c,0xd7,0x1e,0x9b,0xab,0xc4,0x0e,0x4e,0xf6,0x80,0x7d,
0xee,0x4f,0xf8,0x4d,0x4e,0xdf,0xc5,0xbc,0x6c,0xcc,0x3d,0x36,0x7c,0xe5,0xdc,0xf0,
0x11,0xd0,0xa0,0x81,0xcc,0x26,0xe2,0x12,0x47,0x4b,0x70,0xb6,0x73,0xbc,0x2b,0x43,
0x54,0xe8,0xff,0x3b
};
static const unsigned char IM14[37] = {
0xb2,0x02,0xe7,0x12,0x9b,0x75,0xb6,0x72,0xcd,0xd6,0x6e,0x07,0x15,0xf2,0x58,0x5c,
0x37,0x58,0x40,0x03,0x91,0x4c,0xcb,0x89,0xaf,0xe1,0xc4,0xce,0x68,0x94,0x1f,0x6a,
0xd9,0xd3,0xce,0x57,0xb5
};
static const unsigned char IM15[98] = {
0xa2,0xee,0xd4,0x12,0x9b,0x75,0xb6,0x72,0xcd,0xd6,0x6e,0x50,0xc9,0xab,0x93,0x4f,
0x24,0xd3,0x2e,0x88,0x8c,0x75,0xb9,0xfc,0x64,0xd0,0x62,0xce,0x68,0x94,0x1f,0xcd,
0x37,0x3f,0x61,0x7d,0xd1,0x3c,0xd7,0x1e,0x9b,0xab,0xc4,0xa9,0x53,0xc9,0x8a,0xa6,
0xf6,0x4e,0xf8,0x4d,0x4e,0xdf,0xc5,0x1b,0x71,0xf3,0xba,0x2e,0x92,0xb8,0x90,0x3b,
0x4b,0xfc,0xc1,0xbc,0x22,0x0b,0xfa,0xfc,0xd1,0xa0,0xb7,0xf0,0xac,0xbc,0x2b,0x43,
0x54,0x56,0x8b,0x52,0x71,0x0f,0xa5,0x81,0xd9,0xa2,0xbc,0x4f,0x8a,0x3e,0x1d,0xff,
0xe7,0xe0
};
static const unsigned char IM16[42] = {
0xa2,0x39,0x1b,0x4b,0x26,0x4f,0x08,0xb9,0x8c,0x9f,0xcb,0xc1,0x84,0x0f,0x58,0xde,
0xe2,0xd3,0x2e,0x88,0x8c,0xa4,0x72,0xc0,0x10,0x0b,0xf7,0xce,0x68,0x94,0x1f,0x6a,
0xd9,0xee,0x43,0x79,0xd0,0xcf,0x70,0xae,0x7d,0xce
};
static const unsigned char IM17[36] = {
0xa8,0x8b,0xd2,0xc9,0x8c,0x22,0x39,0x08,0xcd,0xeb,0x1a,0xd6,0xd9,0x9e,0x01,0xc0,
0x4d,0xd3,0x2e,0x88,0x8c,0x1a,0x06,0x26,0x08,0x51,0x62,0xce,0x68,0x94,0x1f,0x6a,
0xe4,0x9a,0x90,0x18
};
static uint64_t H_jn0_0(uint64_t a0, uint64_t a1, uint64_t a2){(void)a0;(void)a1;(void)a2; return jn0(); }
static uint64_t H_jn1_0(uint64_t a0, uint64_t a1, uint64_t a2){(void)a0;(void)a1;(void)a2; return jn1(); }
static uint64_t H_jn2_0(uint64_t a0, uint64_t a1, uint64_t a2){(void)a0;(void)a1;(void)a2; return jn2(); }
static uint64_t H_jn3_0(uint64_t a0, uint64_t a1, uint64_t a2){(void)a0;(void)a1;(void)a2; return jn3(); }

static uint64_t hc_f4ac(uint64_t a, uint64_t b){ return (uint64_t)((a | b) & ~( a & b)); }
static uint64_t hc_926e(uint64_t a, uint64_t b){ return (uint64_t)((uint64_t)((int64_t)a >> (b & 63u))); }
static uint64_t hc_e62b(uint64_t a, uint64_t b){ return (uint64_t)(a / b); }
static uint64_t hc_51de(uint64_t a, uint64_t b){ return (uint64_t)((uint64_t)(a <= b)); }
static uint64_t hc_12c1(uint64_t a, uint64_t b){ return (uint64_t)((uint64_t)((int64_t)a % (int64_t)b)); }
static uint64_t hc_39a7(uint64_t a, uint64_t b){ return (uint64_t)((uint64_t)((int64_t)a < (int64_t)b)); }
static uint64_t hc_b7f1(uint64_t a, uint64_t b){ return (uint64_t)((uint64_t)((int64_t)a > (int64_t)b)); }
static uint64_t hc_001c(uint64_t a, uint64_t b){ return (uint64_t)(a << (b & 63u)); }
static uint64_t hc_a264(uint64_t a, uint64_t b){ return (uint64_t)((uint64_t)((a ^ b) == 0)); }
static uint64_t hc_bd96(uint64_t a, uint64_t b){ return (uint64_t)(~(~a & ~b)); }
static uint64_t hc_21e0(uint64_t a, uint64_t b){ return (uint64_t)((uint64_t)((a ^ b) != 0)); }

static void h_5466(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k2) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x0775efb6860d1bacull;
    jn3();
}
static void h_4050(vmst *s){ (void)s;

    imx_run(IM2, s);

}
static void h_b324(vmst *s){ (void)s;
    uint64_t rr = s->st[--s->sp];
    uint64_t v1 = (uint64_t)(uint16_t)rr;
    if (((unsigned)s->sp ^ G_k3 ^ 0x88349f99u) == 0u) { s->fr[62] ^= (uint64_t)s->pp * 184ull; }
    s->st[s->sp++] = v1;
}
static void h_3165(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x016cbd1bc11c2238ull;
    jn1();
}
static void h_b33d(vmst *s){ (void)s;
    uint64_t q2 = s->st[--s->sp];
    uint64_t v2 = s->st[--s->sp];
    jn3();
    uint64_t tb;
    s->fr[63] ^= 0xe2d0f38d95fd8ea7ull;
    if (((s->sp ^ (int)G_k3) & 1u) != 0u) { tb = v2 - (uint64_t)(0 - q2); } else { tb = (v2 ^ q2) + ((v2 & q2) << 1); }
    tb ^= 0x0927fa962a65d1f2ull;
    s->fr[62] += (uint64_t)s->pp * 37ull;
    s->fr[63] += (uint64_t)s->pp * 95ull;
    s->st[s->sp++] = tb ^ 0x0927fa962a65d1f2ull;
    tb ^= 0x0927fa962a65d1f2ull;
}
static void h_ca98(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k3) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x6b8c3f2eb70fd1ceull;
    s->fr[63] += (uint64_t)s->pp * 3ull;
}
static void h_1510(vmst *s){ (void)s;

    imx_run(IM1, s);

}
static void h_4f51(vmst *s){ (void)s;
    uint64_t v2 = s->st[--s->sp];
    uint64_t v1 = s->st[--s->sp];
    uint64_t q2 = (uint64_t)((int64_t)v1 <= (int64_t)v2);
    q2 ^= 0xa399a01c75a847d8ull;
    s->fr[60] ^= 0x56e4b89e8ae0d1c9ull;
    if (((unsigned)s->sp ^ G_k2 ^ 0xe57215e8u) == 0u) { s->fr[63] ^= (uint64_t)s->pp * 59ull; }
    s->st[s->sp++] = q2 ^ 0xa399a01c75a847d8ull;
    if (((unsigned)s->sp ^ G_k1 ^ 0xf432f16fu) == 0u) { s->fr[60] ^= (uint64_t)s->pp * 85ull; }
    q2 ^= 0xa399a01c75a847d8ull;
}
static void h_5038(vmst *s){ (void)s;
    jn3();
    s->sp--;
}
static void h_45f9(vmst *s){ (void)s;
    uint64_t tb = s->st[s->sp - 1];
    if (((unsigned)s->sp ^ G_k1 ^ 0xaafc5accu) == 0u) { s->fr[63] ^= (uint64_t)s->pp * 148ull; }
    s->st[s->sp - 1] = s->st[s->sp - 2];
    s->st[s->sp - 2] = tb;
}
static void h_a3ee(vmst *s){ (void)s;
    uint64_t tb = s->st[--s->sp];
    uint64_t ta = s->st[--s->sp];
    s->fr[63] += (uint64_t)s->pp * 89ull;
    uint64_t q2 = (uint64_t)((int64_t)ta >= (int64_t)tb);
    s->st[s->sp++] = q2;
}
static void h_8400(vmst *s){ (void)s;
    uint64_t q3 = s->st[--s->sp];
    jn0();
    uint64_t vv = s->st[--s->sp];
    jn3();
    *(uint32_t *)(uintptr_t)vv = (uint32_t)q3;
}
static void h_2a56(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x89610a04fa589041ull;
    s->fr[63] ^= 0xdc69076d99c6ce83ull;
}
static void h_4892(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k1) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x957586ae616a0fb7ull;
    s->fr[61] += (uint64_t)s->pp * 44ull;
}
static void h_275a(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x1c22b6470ef5a62cull;
    if (((unsigned)s->sp ^ G_k1 ^ 0xea5daa8fu) == 0u) { s->fr[60] ^= (uint64_t)s->pp * 148ull; }
}
static void h_9a63(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x2a0ef9f90ace6ee8ull;
    s->fr[62] ^= 0x0129ca5202265f64ull;
}
static void h_ef91(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k1) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x6abb047a0a3a8d85ull;
    jn0();
}
static void h_0371(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k2) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x3c283a630495aabdull;
    if (((unsigned)s->sp ^ G_k1 ^ 0x4634e7f8u) == 0u) { s->fr[63] ^= (uint64_t)s->pp * 38ull; }
}
static void h_bbb8(vmst *s){ (void)s;
    uint64_t q2 = s->st[--s->sp];
    uint64_t v2 = s->st[--s->sp];
    s->fr[63] += (uint64_t)s->pp * 95ull;
    uint64_t q1 = (uint64_t)((int64_t)(v2 ^ 0x8000000000000000ull) > (int64_t)(q2 ^ 0x8000000000000000ull));
    q1 ^= 0x35f8174279011f7bull;
    if (((unsigned)s->sp ^ G_k3 ^ 0x124d0a9au) == 0u) { s->fr[63] ^= (uint64_t)s->pp * 36ull; }
    s->fr[63] += (uint64_t)s->pp * 43ull;
    s->st[s->sp++] = q1 ^ 0x35f8174279011f7bull;
    q1 ^= 0x35f8174279011f7bull;
}
static void h_5953(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0xae777a9538e243dbull;
    s->fr[62] += (uint64_t)s->pp * 42ull;
}
static void h_5894(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xf3e78742d46e70a2ull;
}
static void h_573a(vmst *s){ (void)s;
    jn3();
    imx_run(IM14, s);

}
static void h_31ab(vmst *s){ (void)s;
    uint64_t rr = s->st[--s->sp];
    uint64_t ta = s->st[--s->sp];
    s->fr[62] ^= 0x3ca681d84d293320ull;
    uint64_t v1 = ta ^ rr;
    v1 ^= 0xecc7548a3ee6356dull;
    s->fr[63] += (uint64_t)s->pp * 51ull;
    s->st[s->sp++] = v1 ^ 0xecc7548a3ee6356dull;
    v1 ^= 0xecc7548a3ee6356dull;
}
static void h_1053(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xc125413d50058e90ull;
}
static void h_1ca7(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k2) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xc5dd312743a7d3e7ull;
    if (((unsigned)s->sp ^ G_k2 ^ 0x2dc1cf06u) == 0u) { s->fr[62] ^= (uint64_t)s->pp * 119ull; }
}
static void h_e25c(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0xdf42be73c0499b91ull;
    jn0();
}
static void h_8f3e(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xc9621dc0a1769496ull;
}
static void h_2b6f(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0xc8dfc2aca1c792c1ull;
    jn1();
}
static void h_0c0b(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k1) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x62505b4805be0727ull;
    s->fr[60] ^= 0x82bf620969d6a36aull;
}
static void h_9182(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x007e487315cf3009ull;
    if (((unsigned)s->sp ^ G_k2 ^ 0x5c53143bu) == 0u) { s->fr[62] ^= (uint64_t)s->pp * 135ull; }
}
static void h_6f3b(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k3) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x94b555237e706497ull;
    s->fr[61] += (uint64_t)s->pp * 63ull;
}
static void h_cb8e(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k3) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x092792118190ee55ull;
    s->fr[60] += (uint64_t)s->pp * 36ull;
}
static void h_fddd(vmst *s){ (void)s;
    uint64_t q2 = s->st[--s->sp];
    uint64_t v2 = s->st[--s->sp];
    uint64_t rr;
    if ((((unsigned)s->pc ^ G_k3) & 1u) == 0u) { rr = v2 & q2; } else { rr = ~(~v2 | ~q2); }
    s->st[s->sp++] = rr;
}
static void h_a61c(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k2) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x9f5a0962016b4d32ull;
    if (((unsigned)s->sp ^ G_k3 ^ 0xb7f69792u) == 0u) { s->fr[62] ^= (uint64_t)s->pp * 136ull; }
}
static void h_881c(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k3) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x94c0a9fd929695faull;
    jn2();
}
static void h_4409(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0xd565fee5d793b991ull;
    s->fr[63] += (uint64_t)s->pp * 31ull;
}
static void h_8178(vmst *s){ (void)s;

    imx_run(IM10, s);
    if (((unsigned)s->sp ^ G_k1 ^ 0xeb807b15u) == 0u) { s->fr[62] ^= (uint64_t)s->pp * 101ull; }
}
static void h_ab36(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x0a000b4d4a9aa8b0ull;
    s->fr[60] ^= 0x234e15f63a0b0a80ull;
}
static void h_d8e6(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k3) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x89b2a4cf4160d6c2ull;
    s->fr[61] ^= 0xb835e6f57b50d9c4ull;
}
static void h_2415(vmst *s){ (void)s;
    uint64_t q2 = s->st[--s->sp];
    uint64_t rr = s->st[--s->sp];
    uint64_t ta = rr % q2;
    if (((unsigned)s->sp ^ G_k1 ^ 0x98cfb815u) == 0u) { s->fr[62] ^= (uint64_t)s->pp * 174ull; }
    s->st[s->sp++] = ta;
}
static void h_9ec5(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k1) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x112ecc5d5d0ebd67ull;
    if (((unsigned)s->sp ^ G_k3 ^ 0xa3a51835u) == 0u) { s->fr[63] ^= (uint64_t)s->pp * 14ull; }
}
static void h_b418(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k2) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xe0708f1026285524ull;
    s->fr[62] += (uint64_t)s->pp * 19ull;
}
static void h_bc3b(vmst *s){ (void)s;
    uint64_t ta = s->st[--s->sp];
    uint64_t q1 = s->st[--s->sp];
    jn3();
    uint64_t v2 = (uint64_t)((int64_t)q1 / (int64_t)ta);
    jn1();
    s->st[s->sp++] = v2;
}
static void h_d479(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x66b97206f40d16efull;
}
static void h_a7aa(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x6d845a56496db87full;
}
static void h_9f07(vmst *s){ (void)s;

    imx_run(IM5, s);

}
static void h_779e(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xab91082a242fcc5bull;
}
static void h_0e22(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x1aeec92ef54d52d4ull;
}
static void h_be11(vmst *s){ (void)s;
    jn1();
    imx_run(IM13, s);
    s->fr[63] ^= 0x9efbb00862f89f01ull;
}
static void h_cc10(vmst *s){ (void)s;
    uint64_t q1 = s->st[--s->sp];
    uint64_t v2 = s->st[--s->sp];
    uint64_t ta = (v2 | q1) & ~( v2 & q1);
    s->st[s->sp++] = ta;
}
static void h_5166(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xfc169c0ac94781fcull;
}
static void h_2973(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x620010422a4163a7ull;
    jn3();
}
static void h_6874(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x9c1bf5508ea6fc27ull;
}
static void h_d0be(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x4d595f864ad245cfull;
}
static void h_d167(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xd0d852c05d0e885cull;
}
static void h_75a6(vmst *s){ (void)s;
    uint64_t v1 = s->st[--s->sp];
    uint64_t q2 = s->st[--s->sp];
    uint64_t tb = q2 % v1;
    if (((unsigned)s->sp ^ G_k1 ^ 0xd1602011u) == 0u) { s->fr[62] ^= (uint64_t)s->pp * 137ull; }
    s->st[s->sp++] = tb;
}
static void h_0d93(vmst *s){ (void)s;
    uint64_t w1 = s->st[--s->sp];
    uint64_t v1 = (~w1 + 1ull);
    s->st[s->sp++] = v1;
}
static void h_a54a(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k1) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x64db1bf6e50bb7b4ull;
    jn3();
}
static void h_b8e7(vmst *s){ (void)s;
    uint64_t tb = s->st[--s->sp];
    uint64_t q2 = s->st[--s->sp];
    uint64_t ta = hc_f4ac(q2, tb);
    s->st[s->sp++] = ta;
}
static void h_5f78(vmst *s){ (void)s;
    uint64_t rr = s->st[--s->sp];
    uint64_t q2 = s->st[--s->sp];
    uint64_t q1 = hc_926e(q2, rr);
    s->fr[63] ^= 0x806f22bd8a2bfa2full;
    q1 ^= 0x666b4ffd54c8871dull;
    if (((unsigned)s->sp ^ G_k1 ^ 0x04f97054u) == 0u) { s->fr[62] ^= (uint64_t)s->pp * 110ull; }
    s->st[s->sp++] = q1 ^ 0x666b4ffd54c8871dull;
    jn3();
    q1 ^= 0x666b4ffd54c8871dull;
}
static void h_8230(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x23bf4c113fecccafull;
    jn2();
}
static void h_8c3d(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0xd02c86a0f2357af5ull;
    jn2();
}
static void h_68cf(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k3) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x9165f3d889a9ce4cull;
    s->fr[61] += (uint64_t)s->pp * 69ull;
}
static void h_c03e(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k2) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xbe87f8ed555cecbfull;
    s->fr[60] ^= 0xafaa97aa58b8e804ull;
}
static void h_441d(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0xfdd0e38f72a95262ull;
    jn0();
}
static void h_7016(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x95729ffe54bf3db5ull;
}
static void h_e83c(vmst *s){ (void)s;
    if (((unsigned)s->sp ^ G_k2 ^ 0xbddfc14du) == 0u) { s->fr[62] ^= (uint64_t)s->pp * 121ull; }
    imx_run(IM15, s);
    s->fr[62] ^= 0xdc64de6f079aa3aeull;
}
static void h_4628(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k2) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x21248d49f0366a4eull;
    jn0();
}
static void h_5374(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xc8d4ec6f5f732a05ull;
}
static void h_9bfd(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0xc1fb3db6fbb60f3cull;
    s->fr[63] += (uint64_t)s->pp * 71ull;
}
static void h_7308(vmst *s){ (void)s;
    uint64_t q1 = s->st[--s->sp];
    uint64_t q2 = s->st[--s->sp];
    uint64_t v1;
    s->fr[62] ^= 0xbf981c4918561d9full;
    if ((((unsigned)s->pc ^ G_k1) & 1u) == 0u) { v1 = (q2 ^ q1) - ((~q2 & q1) << 1); } else { v1 = q2 + (uint64_t)(0 - q1); }
    if (((unsigned)s->sp ^ G_k3 ^ 0x9183b3d8u) == 0u) { s->fr[60] ^= (uint64_t)s->pp * 180ull; }
    v1 ^= 0x18d2abb42b50fe98ull;
    s->fr[63] ^= 0x7e775abd37e01e2cull;
    s->fr[60] += (uint64_t)s->pp * 39ull;
    s->fr[63] ^= 0x64708284f6d8d08full;
    s->st[s->sp++] = v1 ^ 0x18d2abb42b50fe98ull;
    if (((unsigned)s->sp ^ G_k1 ^ 0x41ed3603u) == 0u) { s->fr[63] ^= (uint64_t)s->pp * 128ull; }
    v1 ^= 0x18d2abb42b50fe98ull;
}
static void h_c88f(vmst *s){ (void)s;

    imx_run(IM11, s);

}
static void h_fd33(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k2) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x95af9894d45c04faull;
    s->fr[63] ^= 0x0cc5eddc219c4238ull;
}
static void h_7231(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k2) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x7e086d2bb4c05622ull;
    jn1();
}
static void h_c979(vmst *s){ (void)s;
    uint64_t ta = s->st[--s->sp];
    uint64_t tb = s->st[--s->sp];
    s->fr[62] ^= 0x16a6899ed99d4120ull;
    uint64_t q2 = hc_e62b(tb, ta);
    s->st[s->sp++] = q2;
}
static void h_7349(vmst *s){ (void)s;
    uint64_t rr = s->st[--s->sp];
    uint64_t q2 = s->st[--s->sp];
    uint64_t ta = hc_51de(q2, rr);
    if (((unsigned)s->sp ^ G_k2 ^ 0xb28b8431u) == 0u) { s->fr[60] ^= (uint64_t)s->pp * 186ull; }
    s->st[s->sp++] = ta;
}
static void h_291d(vmst *s){ (void)s;
    uint64_t ta = s->st[--s->sp];
    uint64_t v2 = s->st[--s->sp];
    uint64_t tb = hc_12c1(v2, ta);
    jn3();
    s->st[s->sp++] = tb;
}
static void h_071c(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k3) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x1698bc7547de199eull;
    if (((unsigned)s->sp ^ G_k2 ^ 0x03c5bfd7u) == 0u) { s->fr[61] ^= (uint64_t)s->pp * 28ull; }
}
static void h_41d7(vmst *s){ (void)s;
    uint64_t rr = s->st[--s->sp];
    uint64_t u1;
    s->fr[62] ^= 0x71ffdc61c08b0b5eull;
    if (((s->sp ^ (int)G_k2) & 1u) != 0u) { u1 = ~rr; } else { u1 = rr ^ 0xFFFFFFFFFFFFFFFFull; }
    if (((unsigned)s->sp ^ G_k3 ^ 0x6a21d1b7u) == 0u) { s->fr[62] ^= (uint64_t)s->pp * 20ull; }
    s->st[s->sp++] = u1;
}
static void h_ccfd(vmst *s){ (void)s;
    s->fr[60] += (uint64_t)s->pp * 78ull;
    s->fr[60] ^= 0x1ab196ba0577df55ull;
    s->alive = 0;
}
static void h_ff1c(vmst *s){ (void)s;
    s->fr[63] ^= 0x874c9048c8b43b1aull;
    if (((unsigned)s->sp ^ G_k2 ^ 0x6aa38c66u) == 0u) { s->fr[61] ^= (uint64_t)s->pp * 146ull; }
}
static void h_c8a9(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xa85e436f20b80e81ull;
}
static void h_06f5(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k3) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x8383f00633cc3f2eull;
    jn0();
}
static void h_df13(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k2) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x7291615313d9bf91ull;
    s->fr[63] ^= 0x9c6ab898b96f7f1eull;
}
static void h_b828(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x26b96f1af86017b2ull;
    jn3();
}
static void h_7cda(vmst *s){ (void)s;
    uint64_t v2 = s->st[--s->sp];
    uint64_t v1 = s->st[--s->sp];
    uint64_t q2 = (uint64_t)(v1 < v2);
    q2 ^= 0x14f88373f480e275ull;
    jn2();
    s->st[s->sp++] = q2 ^ 0x14f88373f480e275ull;
    q2 ^= 0x14f88373f480e275ull;
}
static void h_8ee8(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x121675d1fd5d2938ull;
    s->fr[60] += (uint64_t)s->pp * 63ull;
}
static void h_fbb1(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x71feef493b527142ull;
}
static void h_8f18(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k3) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x3fb9cbd30bd26456ull;
    s->fr[62] += (uint64_t)s->pp * 77ull;
}
static void h_f644(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x254738d180116241ull;
}
static void h_21f8(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k2) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x1b9e61ea614f063aull;
    s->fr[60] ^= 0x5d3c7a1130abd371ull;
}
static void h_86db(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x2694b2eb861e8fc9ull;
    if (((unsigned)s->sp ^ G_k2 ^ 0x41e33808u) == 0u) { s->fr[61] ^= (uint64_t)s->pp * 20ull; }
}
static void h_fd49(vmst *s){ (void)s;
    uint64_t v1 = s->st[--s->sp];
    uint64_t u2 = (uint64_t)(uint8_t)v1;
    s->st[s->sp++] = u2;
}
static void h_bc38(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0xe71321585f3019ccull;
    jn2();
}
static void h_3a9b(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0xdade8170b295127dull;
    if (((unsigned)s->sp ^ G_k2 ^ 0xa2f36e32u) == 0u) { s->fr[60] ^= (uint64_t)s->pp * 45ull; }
}
static void h_bf3e(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0xb54e2b1d385730fbull;
    s->fr[61] ^= 0x569fa6f24f423c62ull;
}
static void h_7be3(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xc6f8fe05aad6b27eull;
}
static void h_de79(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k3) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x00243062ebf955ceull;
    if (((unsigned)s->sp ^ G_k1 ^ 0x37a2bf75u) == 0u) { s->fr[61] ^= (uint64_t)s->pp * 65ull; }
}
static void h_3707(vmst *s){ (void)s;
    uint64_t tb = s->st[--s->sp];
    uint64_t v1 = s->st[--s->sp];
    uint64_t q1 = v1 * tb;
    s->fr[62] += (uint64_t)s->pp * 90ull;
    s->st[s->sp++] = q1;
}
static void h_bb5a(vmst *s){ (void)s;
    uint64_t v1 = s->st[--s->sp];
    s->fr[63] ^= 0xac2d67d8712edef2ull;
    uint64_t u1 = (~v1 + 1ull);
    s->fr[61] += (uint64_t)s->pp * 85ull;
    s->st[s->sp++] = u1;
}
static void h_e91e(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x9d590a21ac68db1aull;
    jn2();
}
static void h_80a0(vmst *s){ (void)s;
    uint64_t ta = s->st[--s->sp];
    uint64_t q1 = s->st[--s->sp];
    jn2();
    uint64_t tb = hc_39a7(q1, ta);
    if (((unsigned)s->sp ^ G_k3 ^ 0x8f998546u) == 0u) { s->fr[60] ^= (uint64_t)s->pp * 21ull; }
    s->st[s->sp++] = tb;
}
static void h_d52e(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x5a21516197ce74a9ull;
    s->fr[62] ^= 0xfdc023100275904aull;
}
static void h_1ddb(vmst *s){ (void)s;
    uint64_t v1 = s->st[--s->sp];
    uint64_t q2 = s->st[--s->sp];
    uint64_t rr = hc_b7f1(q2, v1);
    s->fr[63] ^= 0x01055c1d0aa78861ull;
    s->st[s->sp++] = rr;
}
static void h_3e9b(vmst *s){ (void)s;
    uint64_t rr = s->st[--s->sp];
    uint64_t v1 = (uint64_t)!rr;
    s->st[s->sp++] = v1;
}
static void h_2dc9(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xd64dbe6547366e99ull;
}
static void h_6074(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x59b85e2ff31b60aaull;
}
static void h_2701(vmst *s){ (void)s;
    uint64_t q1 = s->st[--s->sp];
    uint64_t v1 = s->st[--s->sp];
    uint64_t ta = (uint64_t)((int64_t)v1 >= (int64_t)q1);
    s->st[s->sp++] = ta;
}
static void h_c5c2(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0xd6abb9f9ed1a4473ull;
    s->fr[61] += (uint64_t)s->pp * 28ull;
}
static void h_da31(vmst *s){ (void)s;
    uint64_t rr = s->st[--s->sp];
    uint64_t q2 = s->st[--s->sp];
    uint64_t v1 = (uint64_t)((q2 ^ rr) == 0);
    s->fr[61] += (uint64_t)s->pp * 7ull;
    s->st[s->sp++] = v1;
}
static void h_fbbc(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x6a8b16e991dc9f09ull;
}
static void h_d016(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k2) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x41ea4243224bb2f6ull;
    if (((unsigned)s->sp ^ G_k2 ^ 0xdca0c633u) == 0u) { s->fr[62] ^= (uint64_t)s->pp * 174ull; }
}
static void h_1a66(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x314292d9a3d64c13ull;
    s->fr[63] += (uint64_t)s->pp * 37ull;
}
static void h_05df(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x17659be1250cc60bull;
}
static void h_0d7b(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xe443b9e7fc4a2080ull;
}
static void h_0b67(vmst *s){ (void)s;

    imx_run(IM6, s);
    s->fr[63] ^= 0xdf9e044bfb3bdee1ull;
}
static void h_3f08(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x3c4d136af35e6c92ull;
    s->fr[61] ^= 0x1e13b49ce6de616eull;
}
static void h_dd97(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x5823d5b7b7ba5d5eull;
    jn2();
}
static void h_a3a0(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k1) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x9a6441bd5a852188ull;
    s->fr[62] ^= 0x7132ca79071da56aull;
}
static void h_9ef8(vmst *s){ (void)s;

    imx_run(IM7, s);

}
static void h_41ce(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x523790033baaf1a1ull;
}
static void h_f077(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xccef7d9ef531c921ull;
}
static void h_6418(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k1) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xf247cf809621d495ull;
    s->fr[61] += (uint64_t)s->pp * 80ull;
}
static void h_0296(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0xd10dee562cfa9558ull;
    s->fr[60] += (uint64_t)s->pp * 16ull;
}
static void h_cecb(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x312a32ef5f2b0c10ull;
    jn0();
}
static void h_e75a(vmst *s){ (void)s;
    uint64_t v1 = s->st[--s->sp];
    uint64_t u2 = (uint64_t)(uint32_t)v1;
    s->st[s->sp++] = u2;
}
static void h_838f(vmst *s){ (void)s;
    uint64_t q3 = s->st[--s->sp];
    uint64_t ad = s->st[--s->sp];
    *(uint64_t *)(uintptr_t)ad = (uint64_t)q3;
}
static void h_8ee2(vmst *s){ (void)s;
    s->fr[60] += (uint64_t)s->pp * 63ull;
    imx_run(IM16, s);

}
static void h_332f(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k2) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x0fc15838929f5351ull;
    s->fr[62] ^= 0x00d97c1505f57f78ull;
}
static void h_80fc(vmst *s){ (void)s;
    uint64_t p2 = s->st[--s->sp];
    s->fr[60] ^= 0x9c65b584af966943ull;
    uint64_t ad = s->st[--s->sp];
    *(uint16_t *)(uintptr_t)ad = (uint16_t)p2;
}
static void h_4522(vmst *s){ (void)s;
    uint64_t v1 = s->st[--s->sp];
    uint64_t rr = s->st[--s->sp];
    uint64_t q2 = hc_001c(rr, v1);
    s->st[s->sp++] = q2;
}
static void h_0873(vmst *s){ (void)s;
    uint64_t v2 = s->st[--s->sp];
    uint64_t q1 = s->st[--s->sp];
    if (((unsigned)s->sp ^ G_k3 ^ 0x398148c6u) == 0u) { s->fr[63] ^= (uint64_t)s->pp * 115ull; }
    uint64_t tb;
    s->fr[62] += (uint64_t)s->pp * 85ull;
    if ((((unsigned)s->pc ^ G_k1) & 1u) == 0u) { tb = (uint64_t)((int64_t)(q1 ^ 0x8000000000000000ull) >= (int64_t)(v2 ^ 0x8000000000000000ull)); } else { tb = (uint64_t)(q1 >= v2); }
    s->st[s->sp++] = tb;
}
static void h_8160(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x74092f3fda590111ull;
}
static void h_ff05(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x24e93f9cd7b9a51eull;
    s->fr[63] += (uint64_t)s->pp * 38ull;
}
static void h_b42f(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k2) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x4fef4b53172565bcull;
    s->fr[61] += (uint64_t)s->pp * 43ull;
}
static void h_1304(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xaf90832cde2191cbull;
}
static void h_59b0(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x129c58dab16cab88ull;
}
static void h_0c12(vmst *s){ (void)s;
    uint64_t tb = s->st[--s->sp];
    uint64_t ta = s->st[--s->sp];
    s->fr[62] ^= 0xbcaeb3f4910c7f2full;
    uint64_t v2 = (ta | tb) + (ta & tb);
    s->st[s->sp++] = v2;
}
static void h_d956(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x502111ed9c371425ull;
}
static void h_84f4(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x43bd8f7cab2efe20ull;
}
static void h_6010(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k3) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x51531e485d0cafdcull;
    if (((unsigned)s->sp ^ G_k1 ^ 0x9a81d3a5u) == 0u) { s->fr[61] ^= (uint64_t)s->pp * 172ull; }
}
static void h_50fd(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x84ee006ac58428eaull;
    if (((unsigned)s->sp ^ G_k2 ^ 0x1cd9cd02u) == 0u) { s->fr[60] ^= (uint64_t)s->pp * 103ull; }
}
static void h_8241(vmst *s){ (void)s;
    uint64_t q3 = s->st[--s->sp];
    uint64_t p2 = s->st[--s->sp];
    *(uint32_t *)(uintptr_t)p2 = (uint32_t)q3;
}
static void h_f882(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k2) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xdaf6e27d36fe352dull;
    jn3();
}
static void h_0a5d(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k2) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x7fa7ccb51188d01bull;
    s->fr[60] += (uint64_t)s->pp * 44ull;
}
static void h_5b08(vmst *s){ (void)s;
    uint64_t q1 = s->st[--s->sp];
    uint64_t ta = s->st[--s->sp];
    uint64_t v1 = hc_a264(ta, q1);
    s->st[s->sp++] = v1;
}
static void h_46f5(vmst *s){ (void)s;
    uint64_t rr = s->st[--s->sp];
    s->fr[60] += (uint64_t)s->pp * 41ull;
    uint64_t ad = (uint64_t)*(uint32_t *)(uintptr_t)rr;
    s->fr[61] ^= 0xa5e16c53a1a6911dull;
    s->st[s->sp++] = ad;
}
static void h_50b8(vmst *s){ (void)s;
    s->fr[60] += (uint64_t)s->pp * 11ull;
    imx_run(IM3, s);

}
static void h_0ee5(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k1) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xdea81de47c3a4be6ull;
    jn3();
}
static void h_4cde(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x421f75a2b30312b0ull;
    s->fr[60] += (uint64_t)s->pp * 35ull;
}
static void h_82b9(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x1a83ff416b56c4afull;
}
static void h_7a1f(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k2) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xb66fde6f02ca375eull;
    if (((unsigned)s->sp ^ G_k1 ^ 0x6c9f8b7fu) == 0u) { s->fr[62] ^= (uint64_t)s->pp * 73ull; }
}
static void h_8dc8(vmst *s){ (void)s;

    imx_run(IM8, s);
    if (((unsigned)s->sp ^ G_k1 ^ 0x7460adfdu) == 0u) { s->fr[63] ^= (uint64_t)s->pp * 184ull; }
}
static void h_18ba(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k3) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xe32471d9f9178977ull;
    s->fr[61] ^= 0x25c635ab4ab2c21aull;
}
static void h_3e0d(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0xb41612364f7856c6ull;
    if (((unsigned)s->sp ^ G_k1 ^ 0x01470086u) == 0u) { s->fr[63] ^= (uint64_t)s->pp * 134ull; }
}
static void h_ce6f(vmst *s){ (void)s;
    s->st[s->sp] = s->st[s->sp - 1];
    s->fr[63] += (uint64_t)s->pp * 43ull;
    s->sp++;
}
static void h_6bc0(vmst *s){ (void)s;
    uint64_t q2 = s->st[--s->sp];
    uint64_t ta = s->st[--s->sp];
    uint64_t q1 = ta - (uint64_t)(0 - q2);
    q1 ^= 0xed4b72e2006ccddcull;
    jn0();
    s->fr[60] += (uint64_t)s->pp * 38ull;
    s->fr[61] ^= 0xb86e3b730c1de505ull;
    s->st[s->sp++] = q1 ^ 0xed4b72e2006ccddcull;
    jn0();
    q1 ^= 0xed4b72e2006ccddcull;
}
static void h_5f61(vmst *s){ (void)s;
    uint64_t q1 = s->st[--s->sp];
    uint64_t v2 = s->st[--s->sp];
    if (((unsigned)s->sp ^ G_k1 ^ 0x2b3c36e3u) == 0u) { s->fr[63] ^= (uint64_t)s->pp * 98ull; }
    uint64_t ta = hc_bd96(v2, q1);
    ta ^= 0x68351cb326f4c84cull;
    s->fr[61] ^= 0xbdb845964bcc52bdull;
    jn2();
    s->st[s->sp++] = ta ^ 0x68351cb326f4c84cull;
    jn1();
    ta ^= 0x68351cb326f4c84cull;
}
static void h_1b05(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x43004bfcfb9e5156ull;
    if (((unsigned)s->sp ^ G_k1 ^ 0xd299df75u) == 0u) { s->fr[60] ^= (uint64_t)s->pp * 55ull; }
}
static void h_579f(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x7edb0d72c9efab80ull;
    jn2();
}
static void h_0a9f(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k2) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x8e5a6680c1395782ull;
    jn3();
}
static void h_68f9(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k1) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xb39fc2b6f4ef9c90ull;
    jn1();
}
static void h_eff5(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k1) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x4bf3e91fd84fc111ull;
    if (((unsigned)s->sp ^ G_k1 ^ 0x4b9ea384u) == 0u) { s->fr[63] ^= (uint64_t)s->pp * 23ull; }
}
static void h_0596(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0xe7a49b8f5ed8f6e9ull;
    jn0();
}
static void h_7c0c(vmst *s){ (void)s;
    unsigned char o9 = nxb3(s); unsigned char q = (unsigned char)(o9 ^ dmx(s->lp));
    const unsigned char *bc2 = (const unsigned char *)(G_vmt[q].bcp ^ (uint64_t)G_mk);
    unsigned char na = G_vmt[q].na; uint64_t rr[3]; rr[0] = rr[1] = rr[2] = 0;
    s->fr[62] += (uint64_t)s->pp * 52ull;
    while (na > 0) { rr[--na] = s->st[--s->sp]; }
    vm_exec_core(bc2, G_vmt[q].n, G_vmt[q].na, rr);
    s->st[s->sp++] = rr[0];
}
static void h_cddb(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x8c3131c899aff491ull;
}
static void h_e4a2(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k3) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x64a7243c7ff6adf6ull;
    s->fr[63] += (uint64_t)s->pp * 55ull;
}
static void h_dc9f(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xd28286d27fd069ebull;
}
static void h_5a64(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x321e6699c371e00cull;
}
static void h_b303(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k2) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xb4a2341945c0dce3ull;
    jn3();
}
static void h_4989(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x0f747f05b1392203ull;
}
static void h_468d(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k1) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x13b75934f440e8fdull;
    s->fr[60] += (uint64_t)s->pp * 86ull;
}
static void h_677a(vmst *s){ (void)s;
    uint64_t rr = s->st[--s->sp];
    uint64_t v1 = (uint64_t)(uint8_t)rr;
    s->fr[62] ^= 0xd7ebab5e5192aac3ull;
    s->st[s->sp++] = v1;
}
static void h_e704(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x0705bdbfcf240673ull;
}
static void h_bb9a(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k1) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xa43650afa20c0920ull;
    if (((unsigned)s->sp ^ G_k1 ^ 0x1ef9b3ddu) == 0u) { s->fr[61] ^= (uint64_t)s->pp * 59ull; }
}
static void h_8e32(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x20cc5658088a3898ull;
    if (((unsigned)s->sp ^ G_k1 ^ 0x7c71b0a6u) == 0u) { s->fr[63] ^= (uint64_t)s->pp * 47ull; }
}
static void h_4356(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x53bd6f0d2e476efaull;
}
static void h_9c1f(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k3) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xda39418620b37c85ull;
    if (((unsigned)s->sp ^ G_k2 ^ 0xd52e5d5du) == 0u) { s->fr[60] ^= (uint64_t)s->pp * 41ull; }
}
static void h_6141(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k2) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x4c51ab40ed5affe9ull;
    s->fr[61] ^= 0x909215f9795dff0bull;
}
static void h_9936(vmst *s){ (void)s;

    imx_run(IM0, s);

}
static void h_f6bf(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x00f06f92acb88878ull;
    jn2();
}
static void h_1a3f(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x65735af95d6535fdull;
    jn3();
}
static void h_3381(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x136edd075d9453e3ull;
}
static void h_f58a(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x7836f1f097d81891ull;
    s->fr[62] ^= 0x1a48be4ee8384bdfull;
}
static void h_a3cf(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x9cb4de2e4c46715full;
    s->fr[60] += (uint64_t)s->pp * 38ull;
}
static void h_d3cc(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k2) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x77ef2f254e236308ull;
    if (((unsigned)s->sp ^ G_k3 ^ 0xfab86b78u) == 0u) { s->fr[63] ^= (uint64_t)s->pp * 194ull; }
}
static void h_481c(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k3) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xc8f09e377357acbcull;
    if (((unsigned)s->sp ^ G_k2 ^ 0x9561be4bu) == 0u) { s->fr[62] ^= (uint64_t)s->pp * 32ull; }
}
static void h_64a1(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k3) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x7ee418cf4457db60ull;
    if (((unsigned)s->sp ^ G_k3 ^ 0x381e59f7u) == 0u) { s->fr[62] ^= (uint64_t)s->pp * 137ull; }
}
static void h_1c31(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xe77f5d53f364f2adull;
}
static void h_a836(vmst *s){ (void)s;
    uint64_t q1 = s->st[--s->sp];
    uint64_t ta = s->st[--s->sp];
    uint64_t rr = (uint64_t)(ta > q1);
    s->st[s->sp++] = rr;
}
static void h_dbad(vmst *s){ (void)s;
    uint64_t p1 = s->st[--s->sp];
    uint64_t ad = (uint64_t)*(uint8_t *)(uintptr_t)p1;
    s->st[s->sp++] = ad;
}
static void h_2309(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x1b5d966a2838e753ull;
}
static void h_4be4(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k1) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xb00ebc630461b1c4ull;
    jn1();
}
static void h_7409(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xeafebff2d0dfc2e4ull;
}
static void h_5b77(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x20cc30fe1fd858cfull;
    s->fr[63] ^= 0x4c46f3855dfdab5eull;
}
static void h_48f0(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k3) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x43690d9e4046313full;
    s->fr[61] += (uint64_t)s->pp * 56ull;
}
static void h_9b78(vmst *s){ (void)s;
    uint64_t p2 = s->st[--s->sp];
    s->fr[60] += (uint64_t)s->pp * 21ull;
    uint64_t ad = s->st[--s->sp];
    *(uint64_t *)(uintptr_t)ad = (uint64_t)p2;
}
static void h_16da(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xb5920f8c1a75a4f4ull;
}
static void h_8c7a(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0xb5d79a8f9478a8b9ull;
    s->fr[63] += (uint64_t)s->pp * 92ull;
}
static void h_0318(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0xa22094c6b7c2ea94ull;
    jn0();
}
static void h_16e7(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k2) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x411ba4cba876413aull;
    s->fr[60] += (uint64_t)s->pp * 5ull;
}
static void h_7736(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x473c715e6a43ca60ull;
    s->fr[63] ^= 0xf6159a601d04f4afull;
}
static void h_4c3a(vmst *s){ (void)s;
    uint64_t ta = s->st[--s->sp];
    uint64_t q1 = s->st[--s->sp];
    s->fr[62] ^= 0xff3ca2160383c850ull;
    uint64_t rr;
    if ((((unsigned)s->pc ^ G_k2) & 1u) == 0u) { rr = ~(~q1 | ~ta); } else { rr = (q1 | ta) ^ (q1 ^ ta); }
    rr ^= 0x0f1e4fa622ca9f9aull;
    jn3();
    s->fr[62] += (uint64_t)s->pp * 13ull;
    s->fr[61] += (uint64_t)s->pp * 55ull;
    s->st[s->sp++] = rr ^ 0x0f1e4fa622ca9f9aull;
    if (((unsigned)s->sp ^ G_k1 ^ 0x9ac6e586u) == 0u) { s->fr[60] ^= (uint64_t)s->pp * 4ull; }
    rr ^= 0x0f1e4fa622ca9f9aull;
}
static void h_755c(vmst *s){ (void)s;
    uint64_t v2 = s->st[--s->sp];
    uint64_t q1 = s->st[--s->sp];
    uint64_t tb;
    s->fr[60] ^= 0x592714e67fcf5ae0ull;
    if ((((unsigned)s->pc ^ G_k3) & 1u) == 0u) { tb = (uint64_t)(q1 < v2); } else { tb = (uint64_t)((int64_t)(q1 ^ 0x8000000000000000ull) < (int64_t)(v2 ^ 0x8000000000000000ull)); }
    if (((unsigned)s->sp ^ G_k3 ^ 0x0170684eu) == 0u) { s->fr[60] ^= (uint64_t)s->pp * 86ull; }
    s->st[s->sp++] = tb;
}
static void h_324c(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k1) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xbf29f15e6e11dfa8ull;
    s->fr[62] ^= 0x2bb7e43ddb1860f7ull;
}
static void h_f66f(vmst *s){ (void)s;
    uint64_t v1 = s->st[--s->sp];
    jn2();
    uint64_t u1;
    if (((unsigned)s->sp ^ G_k2 ^ 0x66a1546cu) == 0u) { s->fr[62] ^= (uint64_t)s->pp * 14ull; }
    if ((((unsigned)s->pp ^ G_k2) & 3u) < 2u) { u1 = ~v1; } else { u1 = v1 ^ 0xFFFFFFFFFFFFFFFFull; }
    s->st[s->sp++] = u1;
}
static void h_5203(vmst *s){ (void)s;
    jn1();
    imx_run(IM17, s);
    s->fr[62] ^= 0x720feafe8e914a3eull;
}
static void h_2a99(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x6d14b25d8821a18aull;
}
static void h_a871(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x4cb662d3ef4f66c5ull;
}
static void h_3d93(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k2) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x78c653d38e72d3cfull;
    if (((unsigned)s->sp ^ G_k3 ^ 0x919b3e19u) == 0u) { s->fr[61] ^= (uint64_t)s->pp * 140ull; }
}
static void h_0438(vmst *s){ (void)s;
    uint64_t q1 = s->st[--s->sp];
    uint64_t v1 = s->st[--s->sp];
    if (((unsigned)s->sp ^ G_k1 ^ 0xee6e29b8u) == 0u) { s->fr[60] ^= (uint64_t)s->pp * 4ull; }
    uint64_t tb;
    if ((((unsigned)s->pc ^ G_k2) & 1u) == 0u) { tb = (uint64_t)((int64_t)(v1 ^ 0x8000000000000000ull) <= (int64_t)(q1 ^ 0x8000000000000000ull)); } else { tb = (uint64_t)(v1 <= q1); }
    s->st[s->sp++] = tb;
}
static void h_9098(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0xea793fef3b70c3baull;
    s->fr[62] += (uint64_t)s->pp * 21ull;
}
static void h_54f1(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xf57d6deb6420aa21ull;
}
static void h_74c2(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xe5b61cfae867d56cull;
}
static void h_b5d5(vmst *s){ (void)s;
    s->fr[62] += (uint64_t)s->pp * 58ull;
    imx_run(IM12, s);
    jn1();
}
static void h_5d4e(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x681ba47e76549225ull;
}
static void h_8a1e(vmst *s){ (void)s;
    uint64_t u2 = s->st[--s->sp];
    s->fr[61] ^= 0xce4649003ceaa831ull;
    uint64_t rr = (uint64_t)(uint32_t)u2;
    s->st[s->sp++] = rr;
}
static void h_d545(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x797942d978ad3ce9ull;
}
static void h_7e18(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x73b8c846438bdd80ull;
}
static void h_86bc(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k2) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x48a58b1ace6f9a01ull;
    if (((unsigned)s->sp ^ G_k2 ^ 0x0cb76843u) == 0u) { s->fr[63] ^= (uint64_t)s->pp * 88ull; }
}
static void h_71b0(vmst *s){ (void)s;
    uint64_t q1 = s->st[--s->sp];
    s->fr[61] ^= 0x95bc76682673388dull;
    uint64_t ad = (uint64_t)*(uint64_t *)(uintptr_t)q1;
    s->st[s->sp++] = ad;
}
static void h_9db2(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x5e5abcd71f56fb20ull;
}
static void h_24f4(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k2) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x118bd866b41d7362ull;
    jn2();
}
static void h_44cc(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x13e93b6f1e4e186dull;
    jn2();
}
static void h_6243(vmst *s){ (void)s;
    unsigned char o9 = nxb0(s); unsigned char q = (unsigned char)(o9 ^ dmx(s->lp));
    const unsigned char *bc2 = (const unsigned char *)(G_vmt[q].bcp ^ (uint64_t)G_mk);
    unsigned char na = G_vmt[q].na; uint64_t rr[3]; rr[0] = rr[1] = rr[2] = 0;
    if (((unsigned)s->sp ^ G_k3 ^ 0x579bb6b5u) == 0u) { s->fr[61] ^= (uint64_t)s->pp * 85ull; }
    while (na > 0) { rr[--na] = s->st[--s->sp]; }
    vm_exec_core(bc2, G_vmt[q].n, G_vmt[q].na, rr);
    s->st[s->sp++] = rr[0];
}
static void h_4e48(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k3) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xe8e475fb63991fa1ull;
    s->fr[63] += (uint64_t)s->pp * 18ull;
}
static void h_886c(vmst *s){ (void)s;
    uint64_t ta = s->st[--s->sp];
    uint64_t v2 = s->st[--s->sp];
    uint64_t v1 = v2 << (ta & 63u);
    v1 ^= 0x2f2428b858136815ull;
    if (((unsigned)s->sp ^ G_k3 ^ 0xc2a017abu) == 0u) { s->fr[61] ^= (uint64_t)s->pp * 146ull; }
    s->fr[63] ^= 0xe93249b04e8e18dbull;
    s->st[s->sp++] = v1 ^ 0x2f2428b858136815ull;
    v1 ^= 0x2f2428b858136815ull;
}
static void h_d237(vmst *s){ (void)s;
    uint64_t q2 = s->st[--s->sp];
    uint64_t q1 = s->st[--s->sp];
    if (((unsigned)s->sp ^ G_k2 ^ 0xf8896edbu) == 0u) { s->fr[60] ^= (uint64_t)s->pp * 100ull; }
    uint64_t v2 = q1 >> (q2 & 63u);
    s->st[s->sp++] = v2;
}
static void h_7a02(vmst *s){ (void)s;
    uint64_t ad = s->st[--s->sp];
    jn0();
    uint64_t p2 = s->st[--s->sp];
    jn0();
    *(uint8_t *)(uintptr_t)p2 = (uint8_t)ad;
}
static void h_a59b(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k3) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x04b0bd2297a480f8ull;
    s->fr[60] ^= 0x7caa5f8845650997ull;
}
static void h_fe05(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x2af2c1466c761a4bull;
}
static void h_814d(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x72e7dec1cb22d458ull;
    s->fr[62] += (uint64_t)s->pp * 70ull;
}
static void h_2a73(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x551ceabae4e62976ull;
    s->fr[61] ^= 0x66bee7e0ad78efb1ull;
}
static void h_8dae(vmst *s){ (void)s;

    imx_run(IM4, s);
    jn2();
}
static void h_e4cd(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k1) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x1d0d7bd0af205777ull;
    jn0();
}
static void h_5d22(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k3) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xe161f7a086e439c9ull;
    s->fr[62] ^= 0x36e6f1c5b5c33e34ull;
}
static void h_99e2(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x8b121a02105dad42ull;
    s->fr[61] += (uint64_t)s->pp * 54ull;
}
static void h_a626(vmst *s){ (void)s;
    uint64_t tb = s->st[--s->sp];
    uint64_t q2 = s->st[--s->sp];
    uint64_t ta = hc_21e0(q2, tb);
    jn3();
    s->st[s->sp++] = ta;
}
static void h_a5ed(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k1) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x4709acbe230c5a08ull;
    if (((unsigned)s->sp ^ G_k2 ^ 0x84e80112u) == 0u) { s->fr[61] ^= (uint64_t)s->pp * 99ull; }
}
static void h_cdca(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x51d3ae605ba1b514ull;
}
static void h_d3b3(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x35ae0b2141eb9e69ull;
    s->fr[60] ^= 0x5f31c4273f0434b6ull;
}
static void h_bccf(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k1) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x6cfd8a7bf198d18eull;
    s->fr[61] += (uint64_t)s->pp * 65ull;
}
static void h_3717(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k2) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xdadf6b107c2195dcull;
    s->fr[63] += (uint64_t)s->pp * 30ull;
}
static void h_8a47(vmst *s){ (void)s;
    if ((((unsigned)s->pc ^ G_k3) & 1u) == 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x42dd0bf3d0a0e81bull;
    s->fr[63] += (uint64_t)s->pp * 31ull;
}
static void h_8946(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0xbe8724c65894c8a9ull;
}
static void h_a874(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k2) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x12f72526206c1204ull;
    s->fr[61] ^= 0x1ab16b5b12be877full;
}
static void h_7510(vmst *s){ (void)s;
    uint64_t q1 = s->st[--s->sp];
    s->fr[60] ^= 0x4d1d76b3776f3f2eull;
    uint64_t ad = (uint64_t)*(uint16_t *)(uintptr_t)q1;
    s->st[s->sp++] = ad;
}
static void h_defd(vmst *s){ (void)s;
    unsigned char o0 = nxb2(s); unsigned char q = (unsigned char)(o0 ^ dmx(s->lp));
    unsigned char na = G_harn[q]; uint64_t av[3]; unsigned char aj;
    av[0] = 0; av[1] = 0; av[2] = 0;
    s->fr[62] += (uint64_t)s->pp * 32ull;
    for (aj = na; aj > 0; aj--) av[aj - 1] = s->st[--s->sp];
    uint64_t (*hf)(uint64_t, uint64_t, uint64_t) =
        (uint64_t (*)(uint64_t, uint64_t, uint64_t))(G_host[q] ^ (uint64_t)G_mk);

    s->st[s->sp++] = hf(av[0], av[1], av[2]);
}
static void h_105b(vmst *s){ (void)s;
    if (((s->sp ^ (int)G_k3) & 1u) != 0u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xc0bc60c4a9f30bf3ull;
    s->fr[62] += (uint64_t)s->pp * 28ull;
}
static void h_8d12(vmst *s){ (void)s;
    uint64_t ad = s->st[--s->sp];
    s->fr[63] ^= 0x1996032b51dcbff1ull;
    uint64_t rr = (uint64_t)*(uint64_t *)(uintptr_t)ad;
    s->st[s->sp++] = rr;
}
static void h_63a4(vmst *s){ (void)s;

    imx_run(IM9, s);

}
static void h_e66c(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k1) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0xff4c6a9bc81ddfdfull;
    jn0();
}
static void h_1f0b(vmst *s){ (void)s;
    s->sp = 0; s->alive = 0; s->fr[0] = s->fr[0] ^ 0x115281a7bdb9cbd2ull;
    if (((unsigned)s->sp ^ G_k3 ^ 0xc23e8c38u) == 0u) { s->fr[63] ^= (uint64_t)s->pp * 134ull; }
}
static void h_a567(vmst *s){ (void)s;
    uint64_t ta = s->st[--s->sp];
    uint64_t q1 = s->st[--s->sp];
    uint64_t v1 = (uint64_t)((int64_t)q1 < (int64_t)ta);
    if (((unsigned)s->sp ^ G_k3 ^ 0x7b3e171du) == 0u) { s->fr[61] ^= (uint64_t)s->pp * 128ull; }
    s->st[s->sp++] = v1;
}
static void h_4f69(vmst *s){ (void)s;
    if ((((unsigned)s->pp ^ G_k1) & 3u) < 2u) { s->alive = 0; s->sp = 0; }
    else { s->sp = 0; s->alive = 0; }
    s->fr[0] ^= 0x8f1bea874478c5d4ull;
    s->fr[61] += (uint64_t)s->pp * 31ull;
}
static void h_a3b3(vmst *s){ (void)s;
    s->alive = 0; s->sp = 0; s->fr[0] ^= 0x6a24291d6675eaaaull;
}

static void kload(void){
    uint32_t a = dec_bmp_probe() ^ dec_rle_scan();
    uint32_t b = dec_jpeg_idct() + dec_huff_walk();
    uint32_t c = dec_md5_mix() ^ dec_quant_check() ^ dec_png_crc();
    if (IsDebuggerPresent()) { a ^= 0x35d31fu; b += 7u; }
    G_k1 = rotl(a, 3) ^ 0x029a1cc5u;
    G_k2 = (b * 0x6acdu) ^ 0x6e12f284u;
    G_k3 = c + 0xd813dac4u;
    G_b1 = G_k1; G_b2 = G_k2; G_b3 = G_k3;
    G_mk = (uint64_t)(uintptr_t)(rotl(G_k1, 9) + G_k2) ^ 0x3dc4e669ull;
    G_i1 = (dec_huff_walk() ^ dec_md5_mix()) ^ 0x2a700257u;
    G_i2 = ((dec_rle_scan() + dec_png_crc()) * 0x5f1bu) ^ 0xaa70321cu;
    G_i3 = (dec_bmp_probe() ^ dec_jpeg_idct() ^ dec_quant_check()) + 0x48d5e510u;
    G_imk = (uint64_t)(uintptr_t)(rotl(G_i1, 7) + G_i2) ^ 0x986ab66eull;
}

static long g_init;
static void vm_init(void){
    unsigned i, j;
    if (g_init) return;
    g_init = 1;
    kload();
    G_t[235] = (uintptr_t)&h_5466 ^ (uintptr_t)G_mk;
    G_t[38] = (uintptr_t)&h_4050 ^ (uintptr_t)G_mk;
    G_t[87] = (uintptr_t)&h_b324 ^ (uintptr_t)G_mk;
    G_t[174] = (uintptr_t)&h_3165 ^ (uintptr_t)G_mk;
    G_t[73] = (uintptr_t)&h_b33d ^ (uintptr_t)G_mk;
    G_t[156] = (uintptr_t)&h_ca98 ^ (uintptr_t)G_mk;
    G_t[33] = (uintptr_t)&h_1510 ^ (uintptr_t)G_mk;
    G_t[98] = (uintptr_t)&h_4f51 ^ (uintptr_t)G_mk;
    G_t[227] = (uintptr_t)&h_5038 ^ (uintptr_t)G_mk;
    G_t[221] = (uintptr_t)&h_45f9 ^ (uintptr_t)G_mk;
    G_t[24] = (uintptr_t)&h_a3ee ^ (uintptr_t)G_mk;
    G_t[58] = (uintptr_t)&h_8400 ^ (uintptr_t)G_mk;
    G_t[126] = (uintptr_t)&h_2a56 ^ (uintptr_t)G_mk;
    G_t[22] = (uintptr_t)&h_4892 ^ (uintptr_t)G_mk;
    G_t[49] = (uintptr_t)&h_275a ^ (uintptr_t)G_mk;
    G_t[171] = (uintptr_t)&h_9a63 ^ (uintptr_t)G_mk;
    G_t[63] = (uintptr_t)&h_ef91 ^ (uintptr_t)G_mk;
    G_t[254] = (uintptr_t)&h_0371 ^ (uintptr_t)G_mk;
    G_t[241] = (uintptr_t)&h_bbb8 ^ (uintptr_t)G_mk;
    G_t[11] = (uintptr_t)&h_5953 ^ (uintptr_t)G_mk;
    G_t[86] = (uintptr_t)&h_5894 ^ (uintptr_t)G_mk;
    G_t[202] = (uintptr_t)&h_573a ^ (uintptr_t)G_mk;
    G_t[65] = (uintptr_t)&h_31ab ^ (uintptr_t)G_mk;
    G_t[239] = (uintptr_t)&h_1053 ^ (uintptr_t)G_mk;
    G_t[220] = (uintptr_t)&h_1ca7 ^ (uintptr_t)G_mk;
    G_t[129] = (uintptr_t)&h_e25c ^ (uintptr_t)G_mk;
    G_t[157] = (uintptr_t)&h_8f3e ^ (uintptr_t)G_mk;
    G_t[83] = (uintptr_t)&h_2b6f ^ (uintptr_t)G_mk;
    G_t[138] = (uintptr_t)&h_0c0b ^ (uintptr_t)G_mk;
    G_t[137] = (uintptr_t)&h_9182 ^ (uintptr_t)G_mk;
    G_t[120] = (uintptr_t)&h_6f3b ^ (uintptr_t)G_mk;
    G_t[3] = (uintptr_t)&h_cb8e ^ (uintptr_t)G_mk;
    G_t[108] = (uintptr_t)&h_fddd ^ (uintptr_t)G_mk;
    G_t[70] = (uintptr_t)&h_a61c ^ (uintptr_t)G_mk;
    G_t[16] = (uintptr_t)&h_881c ^ (uintptr_t)G_mk;
    G_t[180] = (uintptr_t)&h_4409 ^ (uintptr_t)G_mk;
    G_t[118] = (uintptr_t)&h_8178 ^ (uintptr_t)G_mk;
    G_t[53] = (uintptr_t)&h_ab36 ^ (uintptr_t)G_mk;
    G_t[198] = (uintptr_t)&h_d8e6 ^ (uintptr_t)G_mk;
    G_t[216] = (uintptr_t)&h_2415 ^ (uintptr_t)G_mk;
    G_t[177] = (uintptr_t)&h_9ec5 ^ (uintptr_t)G_mk;
    G_t[88] = (uintptr_t)&h_b418 ^ (uintptr_t)G_mk;
    G_t[232] = (uintptr_t)&h_bc3b ^ (uintptr_t)G_mk;
    G_t[109] = (uintptr_t)&h_d479 ^ (uintptr_t)G_mk;
    G_t[251] = (uintptr_t)&h_a7aa ^ (uintptr_t)G_mk;
    G_t[68] = (uintptr_t)&h_9f07 ^ (uintptr_t)G_mk;
    G_t[76] = (uintptr_t)&h_779e ^ (uintptr_t)G_mk;
    G_t[60] = (uintptr_t)&h_0e22 ^ (uintptr_t)G_mk;
    G_t[201] = (uintptr_t)&h_be11 ^ (uintptr_t)G_mk;
    G_t[183] = (uintptr_t)&h_cc10 ^ (uintptr_t)G_mk;
    G_t[4] = (uintptr_t)&h_5166 ^ (uintptr_t)G_mk;
    G_t[140] = (uintptr_t)&h_2973 ^ (uintptr_t)G_mk;
    G_t[0] = (uintptr_t)&h_6874 ^ (uintptr_t)G_mk;
    G_t[94] = (uintptr_t)&h_d0be ^ (uintptr_t)G_mk;
    G_t[20] = (uintptr_t)&h_d167 ^ (uintptr_t)G_mk;
    G_t[209] = (uintptr_t)&h_75a6 ^ (uintptr_t)G_mk;
    G_t[39] = (uintptr_t)&h_0d93 ^ (uintptr_t)G_mk;
    G_t[224] = (uintptr_t)&h_a54a ^ (uintptr_t)G_mk;
    G_t[208] = (uintptr_t)&h_b8e7 ^ (uintptr_t)G_mk;
    G_t[21] = (uintptr_t)&h_5f78 ^ (uintptr_t)G_mk;
    G_t[250] = (uintptr_t)&h_8230 ^ (uintptr_t)G_mk;
    G_t[160] = (uintptr_t)&h_8c3d ^ (uintptr_t)G_mk;
    G_t[59] = (uintptr_t)&h_68cf ^ (uintptr_t)G_mk;
    G_t[242] = (uintptr_t)&h_c03e ^ (uintptr_t)G_mk;
    G_t[105] = (uintptr_t)&h_441d ^ (uintptr_t)G_mk;
    G_t[79] = (uintptr_t)&h_7016 ^ (uintptr_t)G_mk;
    G_t[214] = (uintptr_t)&h_e83c ^ (uintptr_t)G_mk;
    G_t[123] = (uintptr_t)&h_4628 ^ (uintptr_t)G_mk;
    G_t[211] = (uintptr_t)&h_5374 ^ (uintptr_t)G_mk;
    G_t[168] = (uintptr_t)&h_9bfd ^ (uintptr_t)G_mk;
    G_t[218] = (uintptr_t)&h_7308 ^ (uintptr_t)G_mk;
    G_t[130] = (uintptr_t)&h_c88f ^ (uintptr_t)G_mk;
    G_t[219] = (uintptr_t)&h_fd33 ^ (uintptr_t)G_mk;
    G_t[223] = (uintptr_t)&h_7231 ^ (uintptr_t)G_mk;
    G_t[147] = (uintptr_t)&h_c979 ^ (uintptr_t)G_mk;
    G_t[52] = (uintptr_t)&h_7349 ^ (uintptr_t)G_mk;
    G_t[124] = (uintptr_t)&h_291d ^ (uintptr_t)G_mk;
    G_t[187] = (uintptr_t)&h_071c ^ (uintptr_t)G_mk;
    G_t[56] = (uintptr_t)&h_41d7 ^ (uintptr_t)G_mk;
    G_t[226] = (uintptr_t)&h_ccfd ^ (uintptr_t)G_mk;
    G_t[196] = (uintptr_t)&h_ff1c ^ (uintptr_t)G_mk;
    G_t[44] = (uintptr_t)&h_c8a9 ^ (uintptr_t)G_mk;
    G_t[114] = (uintptr_t)&h_06f5 ^ (uintptr_t)G_mk;
    G_t[236] = (uintptr_t)&h_df13 ^ (uintptr_t)G_mk;
    G_t[184] = (uintptr_t)&h_b828 ^ (uintptr_t)G_mk;
    G_t[12] = (uintptr_t)&h_7cda ^ (uintptr_t)G_mk;
    G_t[255] = (uintptr_t)&h_8ee8 ^ (uintptr_t)G_mk;
    G_t[61] = (uintptr_t)&h_fbb1 ^ (uintptr_t)G_mk;
    G_t[195] = (uintptr_t)&h_8f18 ^ (uintptr_t)G_mk;
    G_t[84] = (uintptr_t)&h_f644 ^ (uintptr_t)G_mk;
    G_t[106] = (uintptr_t)&h_21f8 ^ (uintptr_t)G_mk;
    G_t[253] = (uintptr_t)&h_86db ^ (uintptr_t)G_mk;
    G_t[176] = (uintptr_t)&h_fd49 ^ (uintptr_t)G_mk;
    G_t[72] = (uintptr_t)&h_bc38 ^ (uintptr_t)G_mk;
    G_t[45] = (uintptr_t)&h_3a9b ^ (uintptr_t)G_mk;
    G_t[185] = (uintptr_t)&h_bf3e ^ (uintptr_t)G_mk;
    G_t[47] = (uintptr_t)&h_7be3 ^ (uintptr_t)G_mk;
    G_t[97] = (uintptr_t)&h_de79 ^ (uintptr_t)G_mk;
    G_t[69] = (uintptr_t)&h_3707 ^ (uintptr_t)G_mk;
    G_t[148] = (uintptr_t)&h_bb5a ^ (uintptr_t)G_mk;
    G_t[144] = (uintptr_t)&h_e91e ^ (uintptr_t)G_mk;
    G_t[230] = (uintptr_t)&h_80a0 ^ (uintptr_t)G_mk;
    G_t[167] = (uintptr_t)&h_d52e ^ (uintptr_t)G_mk;
    G_t[104] = (uintptr_t)&h_1ddb ^ (uintptr_t)G_mk;
    G_t[25] = (uintptr_t)&h_3e9b ^ (uintptr_t)G_mk;
    G_t[85] = (uintptr_t)&h_2dc9 ^ (uintptr_t)G_mk;
    G_t[175] = (uintptr_t)&h_6074 ^ (uintptr_t)G_mk;
    G_t[102] = (uintptr_t)&h_2701 ^ (uintptr_t)G_mk;
    G_t[28] = (uintptr_t)&h_c5c2 ^ (uintptr_t)G_mk;
    G_t[29] = (uintptr_t)&h_da31 ^ (uintptr_t)G_mk;
    G_t[89] = (uintptr_t)&h_fbbc ^ (uintptr_t)G_mk;
    G_t[248] = (uintptr_t)&h_d016 ^ (uintptr_t)G_mk;
    G_t[111] = (uintptr_t)&h_1a66 ^ (uintptr_t)G_mk;
    G_t[244] = (uintptr_t)&h_05df ^ (uintptr_t)G_mk;
    G_t[95] = (uintptr_t)&h_0d7b ^ (uintptr_t)G_mk;
    G_t[82] = (uintptr_t)&h_0b67 ^ (uintptr_t)G_mk;
    G_t[245] = (uintptr_t)&h_3f08 ^ (uintptr_t)G_mk;
    G_t[80] = (uintptr_t)&h_dd97 ^ (uintptr_t)G_mk;
    G_t[2] = (uintptr_t)&h_a3a0 ^ (uintptr_t)G_mk;
    G_t[91] = (uintptr_t)&h_9ef8 ^ (uintptr_t)G_mk;
    G_t[217] = (uintptr_t)&h_41ce ^ (uintptr_t)G_mk;
    G_t[238] = (uintptr_t)&h_f077 ^ (uintptr_t)G_mk;
    G_t[141] = (uintptr_t)&h_6418 ^ (uintptr_t)G_mk;
    G_t[149] = (uintptr_t)&h_0296 ^ (uintptr_t)G_mk;
    G_t[151] = (uintptr_t)&h_cecb ^ (uintptr_t)G_mk;
    G_t[93] = (uintptr_t)&h_e75a ^ (uintptr_t)G_mk;
    G_t[252] = (uintptr_t)&h_838f ^ (uintptr_t)G_mk;
    G_t[229] = (uintptr_t)&h_8ee2 ^ (uintptr_t)G_mk;
    G_t[206] = (uintptr_t)&h_332f ^ (uintptr_t)G_mk;
    G_t[203] = (uintptr_t)&h_80fc ^ (uintptr_t)G_mk;
    G_t[162] = (uintptr_t)&h_4522 ^ (uintptr_t)G_mk;
    G_t[66] = (uintptr_t)&h_0873 ^ (uintptr_t)G_mk;
    G_t[172] = (uintptr_t)&h_8160 ^ (uintptr_t)G_mk;
    G_t[116] = (uintptr_t)&h_ff05 ^ (uintptr_t)G_mk;
    G_t[182] = (uintptr_t)&h_b42f ^ (uintptr_t)G_mk;
    G_t[143] = (uintptr_t)&h_1304 ^ (uintptr_t)G_mk;
    G_t[161] = (uintptr_t)&h_59b0 ^ (uintptr_t)G_mk;
    G_t[19] = (uintptr_t)&h_0c12 ^ (uintptr_t)G_mk;
    G_t[100] = (uintptr_t)&h_d956 ^ (uintptr_t)G_mk;
    G_t[6] = (uintptr_t)&h_84f4 ^ (uintptr_t)G_mk;
    G_t[158] = (uintptr_t)&h_6010 ^ (uintptr_t)G_mk;
    G_t[48] = (uintptr_t)&h_50fd ^ (uintptr_t)G_mk;
    G_t[159] = (uintptr_t)&h_8241 ^ (uintptr_t)G_mk;
    G_t[139] = (uintptr_t)&h_f882 ^ (uintptr_t)G_mk;
    G_t[204] = (uintptr_t)&h_0a5d ^ (uintptr_t)G_mk;
    G_t[127] = (uintptr_t)&h_5b08 ^ (uintptr_t)G_mk;
    G_t[163] = (uintptr_t)&h_46f5 ^ (uintptr_t)G_mk;
    G_t[42] = (uintptr_t)&h_50b8 ^ (uintptr_t)G_mk;
    G_t[240] = (uintptr_t)&h_0ee5 ^ (uintptr_t)G_mk;
    G_t[18] = (uintptr_t)&h_4cde ^ (uintptr_t)G_mk;
    G_t[125] = (uintptr_t)&h_82b9 ^ (uintptr_t)G_mk;
    G_t[249] = (uintptr_t)&h_7a1f ^ (uintptr_t)G_mk;
    G_t[99] = (uintptr_t)&h_8dc8 ^ (uintptr_t)G_mk;
    G_t[43] = (uintptr_t)&h_18ba ^ (uintptr_t)G_mk;
    G_t[153] = (uintptr_t)&h_3e0d ^ (uintptr_t)G_mk;
    G_t[31] = (uintptr_t)&h_ce6f ^ (uintptr_t)G_mk;
    G_t[107] = (uintptr_t)&h_6bc0 ^ (uintptr_t)G_mk;
    G_t[1] = (uintptr_t)&h_5f61 ^ (uintptr_t)G_mk;
    G_t[71] = (uintptr_t)&h_1b05 ^ (uintptr_t)G_mk;
    G_t[231] = (uintptr_t)&h_579f ^ (uintptr_t)G_mk;
    G_t[26] = (uintptr_t)&h_0a9f ^ (uintptr_t)G_mk;
    G_t[96] = (uintptr_t)&h_68f9 ^ (uintptr_t)G_mk;
    G_t[207] = (uintptr_t)&h_eff5 ^ (uintptr_t)G_mk;
    G_t[57] = (uintptr_t)&h_0596 ^ (uintptr_t)G_mk;
    G_t[194] = (uintptr_t)&h_7c0c ^ (uintptr_t)G_mk;
    G_t[46] = (uintptr_t)&h_cddb ^ (uintptr_t)G_mk;
    G_t[246] = (uintptr_t)&h_e4a2 ^ (uintptr_t)G_mk;
    G_t[228] = (uintptr_t)&h_dc9f ^ (uintptr_t)G_mk;
    G_t[64] = (uintptr_t)&h_5a64 ^ (uintptr_t)G_mk;
    G_t[178] = (uintptr_t)&h_b303 ^ (uintptr_t)G_mk;
    G_t[155] = (uintptr_t)&h_4989 ^ (uintptr_t)G_mk;
    G_t[189] = (uintptr_t)&h_468d ^ (uintptr_t)G_mk;
    G_t[222] = (uintptr_t)&h_677a ^ (uintptr_t)G_mk;
    G_t[9] = (uintptr_t)&h_e704 ^ (uintptr_t)G_mk;
    G_t[8] = (uintptr_t)&h_bb9a ^ (uintptr_t)G_mk;
    G_t[243] = (uintptr_t)&h_8e32 ^ (uintptr_t)G_mk;
    G_t[188] = (uintptr_t)&h_4356 ^ (uintptr_t)G_mk;
    G_t[197] = (uintptr_t)&h_9c1f ^ (uintptr_t)G_mk;
    G_t[27] = (uintptr_t)&h_6141 ^ (uintptr_t)G_mk;
    G_t[15] = (uintptr_t)&h_9936 ^ (uintptr_t)G_mk;
    G_t[117] = (uintptr_t)&h_f6bf ^ (uintptr_t)G_mk;
    G_t[154] = (uintptr_t)&h_1a3f ^ (uintptr_t)G_mk;
    G_t[115] = (uintptr_t)&h_3381 ^ (uintptr_t)G_mk;
    G_t[17] = (uintptr_t)&h_f58a ^ (uintptr_t)G_mk;
    G_t[34] = (uintptr_t)&h_a3cf ^ (uintptr_t)G_mk;
    G_t[150] = (uintptr_t)&h_d3cc ^ (uintptr_t)G_mk;
    G_t[164] = (uintptr_t)&h_481c ^ (uintptr_t)G_mk;
    G_t[135] = (uintptr_t)&h_64a1 ^ (uintptr_t)G_mk;
    G_t[212] = (uintptr_t)&h_1c31 ^ (uintptr_t)G_mk;
    G_t[121] = (uintptr_t)&h_a836 ^ (uintptr_t)G_mk;
    G_t[74] = (uintptr_t)&h_dbad ^ (uintptr_t)G_mk;
    G_t[10] = (uintptr_t)&h_2309 ^ (uintptr_t)G_mk;
    G_t[247] = (uintptr_t)&h_4be4 ^ (uintptr_t)G_mk;
    G_t[225] = (uintptr_t)&h_7409 ^ (uintptr_t)G_mk;
    G_t[210] = (uintptr_t)&h_5b77 ^ (uintptr_t)G_mk;
    G_t[62] = (uintptr_t)&h_48f0 ^ (uintptr_t)G_mk;
    G_t[41] = (uintptr_t)&h_9b78 ^ (uintptr_t)G_mk;
    G_t[193] = (uintptr_t)&h_16da ^ (uintptr_t)G_mk;
    G_t[14] = (uintptr_t)&h_8c7a ^ (uintptr_t)G_mk;
    G_t[90] = (uintptr_t)&h_0318 ^ (uintptr_t)G_mk;
    G_t[170] = (uintptr_t)&h_16e7 ^ (uintptr_t)G_mk;
    G_t[132] = (uintptr_t)&h_7736 ^ (uintptr_t)G_mk;
    G_t[101] = (uintptr_t)&h_4c3a ^ (uintptr_t)G_mk;
    G_t[192] = (uintptr_t)&h_755c ^ (uintptr_t)G_mk;
    G_t[7] = (uintptr_t)&h_324c ^ (uintptr_t)G_mk;
    G_t[146] = (uintptr_t)&h_f66f ^ (uintptr_t)G_mk;
    G_t[234] = (uintptr_t)&h_5203 ^ (uintptr_t)G_mk;
    G_t[5] = (uintptr_t)&h_2a99 ^ (uintptr_t)G_mk;
    G_t[50] = (uintptr_t)&h_a871 ^ (uintptr_t)G_mk;
    G_t[81] = (uintptr_t)&h_3d93 ^ (uintptr_t)G_mk;
    G_t[54] = (uintptr_t)&h_0438 ^ (uintptr_t)G_mk;
    G_t[40] = (uintptr_t)&h_9098 ^ (uintptr_t)G_mk;
    G_t[152] = (uintptr_t)&h_54f1 ^ (uintptr_t)G_mk;
    G_t[134] = (uintptr_t)&h_74c2 ^ (uintptr_t)G_mk;
    G_t[166] = (uintptr_t)&h_b5d5 ^ (uintptr_t)G_mk;
    G_t[30] = (uintptr_t)&h_5d4e ^ (uintptr_t)G_mk;
    G_t[133] = (uintptr_t)&h_8a1e ^ (uintptr_t)G_mk;
    G_t[92] = (uintptr_t)&h_d545 ^ (uintptr_t)G_mk;
    G_t[179] = (uintptr_t)&h_7e18 ^ (uintptr_t)G_mk;
    G_t[136] = (uintptr_t)&h_86bc ^ (uintptr_t)G_mk;
    G_t[51] = (uintptr_t)&h_71b0 ^ (uintptr_t)G_mk;
    G_t[23] = (uintptr_t)&h_9db2 ^ (uintptr_t)G_mk;
    G_t[113] = (uintptr_t)&h_24f4 ^ (uintptr_t)G_mk;
    G_t[36] = (uintptr_t)&h_44cc ^ (uintptr_t)G_mk;
    G_t[173] = (uintptr_t)&h_6243 ^ (uintptr_t)G_mk;
    G_t[32] = (uintptr_t)&h_4e48 ^ (uintptr_t)G_mk;
    G_t[145] = (uintptr_t)&h_886c ^ (uintptr_t)G_mk;
    G_t[35] = (uintptr_t)&h_d237 ^ (uintptr_t)G_mk;
    G_t[112] = (uintptr_t)&h_7a02 ^ (uintptr_t)G_mk;
    G_t[131] = (uintptr_t)&h_a59b ^ (uintptr_t)G_mk;
    G_t[181] = (uintptr_t)&h_fe05 ^ (uintptr_t)G_mk;
    G_t[205] = (uintptr_t)&h_814d ^ (uintptr_t)G_mk;
    G_t[190] = (uintptr_t)&h_2a73 ^ (uintptr_t)G_mk;
    G_t[67] = (uintptr_t)&h_8dae ^ (uintptr_t)G_mk;
    G_t[215] = (uintptr_t)&h_e4cd ^ (uintptr_t)G_mk;
    G_t[119] = (uintptr_t)&h_5d22 ^ (uintptr_t)G_mk;
    G_t[122] = (uintptr_t)&h_99e2 ^ (uintptr_t)G_mk;
    G_t[128] = (uintptr_t)&h_a626 ^ (uintptr_t)G_mk;
    G_t[199] = (uintptr_t)&h_a5ed ^ (uintptr_t)G_mk;
    G_t[237] = (uintptr_t)&h_cdca ^ (uintptr_t)G_mk;
    G_t[200] = (uintptr_t)&h_d3b3 ^ (uintptr_t)G_mk;
    G_t[186] = (uintptr_t)&h_bccf ^ (uintptr_t)G_mk;
    G_t[142] = (uintptr_t)&h_3717 ^ (uintptr_t)G_mk;
    G_t[75] = (uintptr_t)&h_8a47 ^ (uintptr_t)G_mk;
    G_t[233] = (uintptr_t)&h_8946 ^ (uintptr_t)G_mk;
    G_t[77] = (uintptr_t)&h_a874 ^ (uintptr_t)G_mk;
    G_t[55] = (uintptr_t)&h_7510 ^ (uintptr_t)G_mk;
    G_t[13] = (uintptr_t)&h_defd ^ (uintptr_t)G_mk;
    G_t[191] = (uintptr_t)&h_105b ^ (uintptr_t)G_mk;
    G_t[78] = (uintptr_t)&h_8d12 ^ (uintptr_t)G_mk;
    G_t[103] = (uintptr_t)&h_63a4 ^ (uintptr_t)G_mk;
    G_t[169] = (uintptr_t)&h_e66c ^ (uintptr_t)G_mk;
    G_t[165] = (uintptr_t)&h_1f0b ^ (uintptr_t)G_mk;
    G_t[213] = (uintptr_t)&h_a567 ^ (uintptr_t)G_mk;
    G_t[37] = (uintptr_t)&h_4f69 ^ (uintptr_t)G_mk;
    G_t[110] = (uintptr_t)&h_a3b3 ^ (uintptr_t)G_mk;
    G_it[4] = (uintptr_t)&g_8575 ^ (uintptr_t)G_imk;
    G_it[5] = (uintptr_t)&g_c6d1 ^ (uintptr_t)G_imk;
    G_it[10] = (uintptr_t)&g_ee01 ^ (uintptr_t)G_imk;
    G_it[18] = (uintptr_t)&g_d98b ^ (uintptr_t)G_imk;
    G_it[22] = (uintptr_t)&g_ba23 ^ (uintptr_t)G_imk;
    G_it[23] = (uintptr_t)&g_493f ^ (uintptr_t)G_imk;
    G_it[24] = (uintptr_t)&g_0d41 ^ (uintptr_t)G_imk;
    G_it[27] = (uintptr_t)&g_b31b ^ (uintptr_t)G_imk;
    G_it[30] = (uintptr_t)&g_bef9 ^ (uintptr_t)G_imk;
    G_it[33] = (uintptr_t)&g_01f2 ^ (uintptr_t)G_imk;
    G_it[34] = (uintptr_t)&g_b13a ^ (uintptr_t)G_imk;
    G_it[42] = (uintptr_t)&g_7d39 ^ (uintptr_t)G_imk;
    G_it[43] = (uintptr_t)&g_666f ^ (uintptr_t)G_imk;
    G_it[45] = (uintptr_t)&g_2e10 ^ (uintptr_t)G_imk;
    G_it[61] = (uintptr_t)&g_a9d0 ^ (uintptr_t)G_imk;
    G_it[66] = (uintptr_t)&g_2dc1 ^ (uintptr_t)G_imk;
    G_it[77] = (uintptr_t)&g_712d ^ (uintptr_t)G_imk;
    G_it[80] = (uintptr_t)&g_2be4 ^ (uintptr_t)G_imk;
    G_it[88] = (uintptr_t)&g_cfe4 ^ (uintptr_t)G_imk;
    G_it[89] = (uintptr_t)&g_7e6c ^ (uintptr_t)G_imk;
    G_it[92] = (uintptr_t)&g_3008 ^ (uintptr_t)G_imk;
    G_it[93] = (uintptr_t)&g_c4b3 ^ (uintptr_t)G_imk;
    G_it[97] = (uintptr_t)&g_acb5 ^ (uintptr_t)G_imk;
    G_it[98] = (uintptr_t)&g_ce9c ^ (uintptr_t)G_imk;
    G_it[101] = (uintptr_t)&g_9a79 ^ (uintptr_t)G_imk;
    G_it[105] = (uintptr_t)&g_e2ed ^ (uintptr_t)G_imk;
    G_it[106] = (uintptr_t)&g_a2af ^ (uintptr_t)G_imk;
    G_it[108] = (uintptr_t)&g_e652 ^ (uintptr_t)G_imk;
    G_it[113] = (uintptr_t)&g_b4fd ^ (uintptr_t)G_imk;
    G_it[116] = (uintptr_t)&g_abf4 ^ (uintptr_t)G_imk;
    G_it[127] = (uintptr_t)&g_b065 ^ (uintptr_t)G_imk;
    G_it[133] = (uintptr_t)&g_ce17 ^ (uintptr_t)G_imk;
    G_it[134] = (uintptr_t)&g_73be ^ (uintptr_t)G_imk;
    G_it[144] = (uintptr_t)&g_d7b7 ^ (uintptr_t)G_imk;
    G_it[157] = (uintptr_t)&g_810f ^ (uintptr_t)G_imk;
    G_it[161] = (uintptr_t)&g_b55b ^ (uintptr_t)G_imk;
    G_it[164] = (uintptr_t)&g_a707 ^ (uintptr_t)G_imk;
    G_it[165] = (uintptr_t)&g_cf08 ^ (uintptr_t)G_imk;
    G_it[167] = (uintptr_t)&g_e5a0 ^ (uintptr_t)G_imk;
    G_it[173] = (uintptr_t)&g_c303 ^ (uintptr_t)G_imk;
    G_it[176] = (uintptr_t)&g_e8fb ^ (uintptr_t)G_imk;
    G_it[177] = (uintptr_t)&g_e7f1 ^ (uintptr_t)G_imk;
    G_it[183] = (uintptr_t)&g_a485 ^ (uintptr_t)G_imk;
    G_it[186] = (uintptr_t)&g_8bc8 ^ (uintptr_t)G_imk;
    G_it[187] = (uintptr_t)&g_2e96 ^ (uintptr_t)G_imk;
    G_it[190] = (uintptr_t)&g_e845 ^ (uintptr_t)G_imk;
    G_it[191] = (uintptr_t)&g_7441 ^ (uintptr_t)G_imk;
    G_it[198] = (uintptr_t)&g_f9f4 ^ (uintptr_t)G_imk;
    G_it[203] = (uintptr_t)&g_ab95 ^ (uintptr_t)G_imk;
    G_it[209] = (uintptr_t)&g_3442 ^ (uintptr_t)G_imk;
    G_it[212] = (uintptr_t)&g_b461 ^ (uintptr_t)G_imk;
    G_it[219] = (uintptr_t)&g_b86a ^ (uintptr_t)G_imk;
    G_it[230] = (uintptr_t)&g_b87b ^ (uintptr_t)G_imk;
    G_it[233] = (uintptr_t)&g_db41 ^ (uintptr_t)G_imk;
    G_it[237] = (uintptr_t)&g_924b ^ (uintptr_t)G_imk;
    G_it[238] = (uintptr_t)&g_2856 ^ (uintptr_t)G_imk;
    G_it[243] = (uintptr_t)&g_fbd8 ^ (uintptr_t)G_imk;
    G_it[246] = (uintptr_t)&g_2a22 ^ (uintptr_t)G_imk;
    G_it[249] = (uintptr_t)&g_1700 ^ (uintptr_t)G_imk;
    G_it[250] = (uintptr_t)&g_5c81 ^ (uintptr_t)G_imk;
    G_host[0] = (uintptr_t)&H_jn0_0 ^ (uintptr_t)G_mk; G_harn[0] = 0;
    G_host[1] = (uintptr_t)&H_jn1_0 ^ (uintptr_t)G_mk; G_harn[1] = 0;
    G_host[2] = (uintptr_t)&H_jn2_0 ^ (uintptr_t)G_mk; G_harn[2] = 0;
    G_host[3] = (uintptr_t)&H_jn3_0 ^ (uintptr_t)G_mk; G_harn[3] = 0;
    G_vmt[0].bcp = (uintptr_t)&BC0[0] ^ (uintptr_t)G_mk; G_vmt[0].n = 442; G_vmt[0].na = 3;
    G_vmt[1].bcp = (uintptr_t)&BC1[0] ^ (uintptr_t)G_mk; G_vmt[1].n = 259; G_vmt[1].na = 2;
    G_vmt[2].bcp = (uintptr_t)&BC2[0] ^ (uintptr_t)G_mk; G_vmt[2].n = 176; G_vmt[2].na = 1;
    G_vmt[3].bcp = (uintptr_t)&BC3[0] ^ (uintptr_t)G_mk; G_vmt[3].n = 324; G_vmt[3].na = 2;
    (void)i;
}

static void vm_exec_core(const unsigned char *bc, uint32_t n,
                         unsigned char na, uint64_t *rv){
    vmst s; unsigned i;
    uint32_t pk1 = G_k1, pk2 = G_k2, pk3 = G_k3;
    G_k1 = G_b1; G_k2 = G_b2; G_k3 = G_b3;
    (void)n;
    s.bc = bc; s.pc = 0; s.pp = 0; s.lp = 0; s.sp = 0; s.alive = 1;
    for (i = 0; i < NFR; i++) s.fr[i] = 0;
    for (i = 0; i < (unsigned)na && i < 3; i++) s.fr[i] = rv[i];
    while (s.alive) {
        unsigned char op = nxb1(&s);

        ((vmhf)(G_t[op] ^ (uint64_t)G_mk))(&s);
    }
    rv[0] = s.fr[0];
    G_k1 = pk1; G_k2 = pk2; G_k3 = pk3;
}
static void vmx_run(unsigned char fid, uint64_t *rv){
    vm_init();
    vm_exec_core((const unsigned char *)(G_vmt[fid].bcp ^ (uint64_t)G_mk),
                 G_vmt[fid].n, G_vmt[fid].na, rv);
}

uint32_t vm_decode_msg(uint8_t* dst, uint8_t* src, uint32_t n);
uint32_t vm_checksum(uint8_t* p, uint32_t n);
uint32_t vm_mix32(uint32_t x);
uint32_t vm_serial_for(char* name, uint32_t len);

uint32_t vm_decode_msg(uint8_t* dst, uint8_t* src, uint32_t n){
    uint64_t rv[3]; rv[0]=rv[1]=rv[2]=0;
    rv[0] = (uint64_t)(uintptr_t)dst;
    rv[1] = (uint64_t)(uintptr_t)src;
    rv[2] = (uint64_t)n;
    if (opq_f(GetTickCount())) { dec_jpeg_idct(); dec_png_crc(); dec_huff_walk(); }
    vmx_run(0, rv);
    return (uint32_t)rv[0];
}
uint32_t vm_checksum(uint8_t* p, uint32_t n){
    uint64_t rv[3]; rv[0]=rv[1]=rv[2]=0;
    rv[0] = (uint64_t)(uintptr_t)p;
    rv[1] = (uint64_t)n;
    if (opq_f(GetTickCount())) { dec_jpeg_idct(); dec_png_crc(); dec_huff_walk(); }
    vmx_run(1, rv);
    return (uint32_t)rv[0];
}
uint32_t vm_mix32(uint32_t x){
    uint64_t rv[3]; rv[0]=rv[1]=rv[2]=0;
    rv[0] = (uint64_t)x;
    if (opq_f(GetTickCount())) { dec_jpeg_idct(); dec_png_crc(); dec_huff_walk(); }
    vmx_run(2, rv);
    return (uint32_t)rv[0];
}
uint32_t vm_serial_for(char* name, uint32_t len){
    uint64_t rv[3]; rv[0]=rv[1]=rv[2]=0;
    rv[0] = (uint64_t)(uintptr_t)name;
    rv[1] = (uint64_t)len;
    if (opq_f(GetTickCount())) { dec_jpeg_idct(); dec_png_crc(); dec_huff_walk(); }
    vmx_run(3, rv);
    return (uint32_t)rv[0];
}

#include "demo/demo_main.c"
