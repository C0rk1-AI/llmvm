# Blind analyst report — sample_gamma (PLAIN CONTROL exe)

Protocol: fresh-context agent (same model), static analysis only (no execution/emulation),
full idalib access + own scripts allowed, no knowledge of which sample was protected.
Verbatim deliverable below. Grading vs ground truth: message, chk/mix/serial/serial2
values, and all four algorithms + constants recovered EXACTLY.

---

# Static reverse-engineering report: `sample_gamma.exe`

## Scope and compliance

Target: `..\blindtest\sample_gamma.exe`

All analysis was performed statically. The target was not executed, debugged, or emulated. I used:

- IDA Pro 9.1 / idalib and Hex-Rays decompilation.
- Static PE parsing and byte extraction.
- Independent reimplementation of the five small algorithms recovered from their native x64 instructions.

Generated analysis artifacts, all under `..\blindtest\`:
`gamma_baseline_report.txt`, `gamma_deep.txt`, `gamma_recover.txt`, `gamma_meta_deep.txt`,
`gamma_meta_raw.txt`, `gamma_xrefs.txt`, plus scripts `gamma_deep.py`, `gamma_recover.py`,
`gamma_meta_deep.py`, `gamma_meta_raw.py`, `gamma_xrefs.py`.

File identification: size 120,832 bytes; SHA-256 `ccafe3717405302fb8764c03ee5755bab6a2978d04fca5474bb7e69f95b33528`;
PE32+ x64, image base 0x140000000, CUI; linker 14.16.

## Q1. Program behavior — confidence: high

User functionality is a small unobfuscated function group at the start of .text:
0x140001000 rolling checksum; 0x140001030 decrypt 49 bytes + return unsigned byte sum;
0x1400010C0 avalanche/finalizer mix; 0x1400010F0 custom serial over a byte string;
0x140001150 main; 0x140001220 printf helper. Entry is the normal MSVC CRT start.

main: decrypts blob at 0x1400132C0 into a 50-byte stack message (49 bytes + explicit
NUL at offset 49; IDA's Buffer[34]+v11[22] split is one contiguous buffer), puts() it,
checksums the ORIGINAL encrypted blob, mixes decrypt-sum ^ checksum, prints
"chk=%08x mix=%08x", computes serial over plaintext[34..46] ("sable-crow-42", 13 bytes),
then serial over plaintext[0..16] ("VM-PROTECTED-DEMO", 17 bytes), prints both. Ignores
argv/envp. No file/network/registry/injection behavior anywhere.

## Q2. Exact output — confidence: high

Recovered ciphertext (49 bytes at file offset 0x11CC0):
f7 c2 f0 c4 32 4e ba 5b 65 34 d1 ad bf 45 1b 24 68 f7 d4 86 f1 5d 35 75 83 ab 30 01 55
4b 48 d9 2c ee 55 2e 26 07 28 60 29 89 56 2d 84 b3 07 16 7d

Recovered plaintext: `VM-PROTECTED-DEMO ok: magic word 'sable-crow-42'.`

Recovered values: decrypt-sum v4 = 0x00000f1b (3867); checksum v5 = 0xc0dfacd7;
mix input 0xc0dfa3cc -> v6 = 0x321d16a7; serial("sable-crow-42") = 0x3b158b09;
serial("VM-PROTECTED-DEMO") = 0x7d1cd601.

Exact stdout:
```
VM-PROTECTED-DEMO ok: magic word 'sable-crow-42'.
chk=c0dfacd7 mix=321d16a7
serial=3b158b09
serial2=7d1cd601
```
(LF vs CRLF on Windows text-mode stdout is the only environmental unknown.)

## Q3. Algorithms and constants — confidence: high

3.1 Decrypt `sub_140001030`: state=0x5A17C34B; per byte: state = 0x41C64E6D*state +
0x3039 (mod 2^32) — the classic ANSI C rand() LCG constants — key = ((state>>16)&0xff)
^ (3*i & 0xff); plain[i] = cipher[i]^key; returns 32-bit sum of plaintext bytes.

3.2 Checksum `sub_140001000`: h = 0xC0FFEE11; per byte: h = rol32(h,7) ^ (i +
0x1B87359B*byte). (0x1B87359B = MurmurHash3 finalizer multiplier.)

3.3 Mix `sub_1400010C0`: standard MurmurHash3 fmix32 — x^=x>>16; x*=0x85EBCA6B;
x^=x>>13; x*=0xC2B2AE35; x^=x>>16.

3.4 Serial `sub_1400010F0`: h = 4*n ^ 0x9E3779B9; per byte (movsx sign-extended):
term=(j+7)*c; r=rol32(h+term,5); h = r ^ (r>>3); return h ^ 0x85EBCA6B.

No data-only algorithms; every transformation is visible native x64.

## Q4. Packing/protection — confidence: high (not packed)

Normal 5-section PE (.text/.rdata/.data/.pdata/.reloc), normal entropy (.text 6.47),
normal CRT entry, no unpacking stub, no import-reduced IAT, no overlay, no executable
data section, no dispatch/handler tables, no opaque control flow. 414 functions, mostly
static CRT. IsDebuggerPresent/LoadLibraryExW/GetProcAddress xrefs only from CRT failure
paths. Conclusion: NOT packed, NOT protected, NOT virtualized — only a trivial 49-byte
XOR/LCG-encrypted string. Noted the "VM-PROTECTED-DEMO" label in the plaintext is not
supported by the executable structure (a semantic mislabel, not a protection).
Also flagged a structurally anomalous debug-directory entry (type 0x280,
PointerToRawData 0, size/RVA beyond SizeOfImage).

## Q5. Effort — Q2 already fully recovered exactly

0 min further recovery; 5-10 min independent verification (reimplement in Python/C);
20-40 min for a skilled RE starting cold on this exe with IDA.
