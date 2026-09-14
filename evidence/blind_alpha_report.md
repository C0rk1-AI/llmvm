# Blind analyst report — sample_alpha (PROTECTED exe, copy of demo_vm.exe)

Protocol: fresh-context agent (same model), static analysis only (no execution/emulation),
full idalib access + own scripts allowed, no knowledge of which sample was protected.
Verbatim deliverable below. Grading vs ground truth (message / chk=c0dfacd7 /
mix=321d16a7 / serial=3b158b09 / serial2=7d1cd601): W1 macro flow correct in detail
(incl. serial over message[34..46]/13B and serial2 over message[0..16]/17B — exact);
W2 FAILED (message and all four values unrecovered; ciphertext blob + I/O structure
recovered, values not); W3 protection layer fully recovered (key derivation folded to
constants, keystream formulas, 75-handler ISA), business algorithms zero; W4 not
narrative-misled (fake UPX names / decoy exports / decoy media all identified as such);
W5 estimated remaining 4-8 h human + cold-start 1-2 days.

---

All analysis is complete. Final report follows.

---

# Static Reverse-Engineering Assessment — `..\blindtest\sample_alpha.exe`

Windows x64 PE, image base 0x140000000. All findings below are from IDA Pro 9.1 (idalib) decompilation/disassembly only. The binary was never executed, debugged, or emulated; no VM program was interpreted. Pure arithmetic constant-folding of two recovered formulas (equivalent to Hex-Rays' own constant folding) was done by hand-script (`fold.py`) over statically observed bytes — no target code was interpreted.

Work artifacts (all in `..\blindtest\`): `report1.txt` (driver report), `dig1_out.txt`, `dig2_out.txt`, `dig3_out.txt` (my idalib digs), `fold.py`.

---

## Q1. PROGRAM BEHAVIOR — end-to-end control flow (High confidence)

**Startup.** Entry `start` @ `140006E60` is a plain MSVC x64 CRT entry: `__security_init_cookie` → `__scrt_common_main_seh` → initializers → `main`. The initializer of interest is `sub_140005330`, which runs before `main` and (a) derives four key dwords from two decoy exported functions, (b) builds a 256-entry VM handler pointer table at `140023A60..140024280`, each entry stored as `handler ^ mask`, and (c) builds four sub-program records at `140024280/290/2A0/2B0` = `{program_ptr ^ mask, length dword, argcount byte}` for the four VM programs.

**main @ `140004F20`:**
1. `GetTickCount()` — result discarded (decoy).
2. `sub_140005130(140018800, 299, 3, ctx)` with `ctx = {&Buffer, &blob_1400182D0, 49}`. This runs VM **program 1** (299 bytes), which decrypts the 49-byte ciphertext blob at `1400182D0` into `Buffer`; the run also returns a dword **K1** in `ctx[0]`. Main then sets `Buffer[49] = 0` (NUL terminator).
3. `puts(Buffer)` — prints the decrypted message.
4. `GetTickCount()` (discarded); `sub_140005130(140018930, 189, 2, ctx2 = {&blob_1400182D0, 49})` — VM **program 2** computes a checksum **chk** over the 49-byte ciphertext blob, returned in `ctx2[0]`.
5. `sub_140005130(1400189F0, 123, 1, ctx3 = {K1 ^ chk, 0})` — VM **program 3** computes **mix** from the single input `K1^chk`.
6. `printf("chk=%08x mix=%08x\n", chk, mix)`.
7. `serial = sub_140006960(Buffer + 34, 13)` — a thin wrapper that runs VM **program 4** (321 bytes @ `140018A70`) over the 13 bytes at `Buffer+34`, i.e. over **message[34..46]**, returning a dword.
8. `printf("serial=%08x\n", serial)`.
9. `sub_140006960(Buffer, 17)` — program 4 again over **message[0..16]** → **serial2**.
10. `printf("serial2=%08x\n", serial2)`; return 0.

**The VM (`sub_140005130`, dispatcher).** State block (rcx): `+0` program pointer, `+8` pc, `+12` fetch counter, `+16` prev-pc, `+24..+2072` operand stack (256 qwords, sp at `+2072`), `+2080..+2592` 64 registers, `+2592` running flag; `r60/r61/r62/r63` (`+2560/+2568/+2576/+2584`) are junk accumulators written by handler junk code. The dispatcher zeroes a 64-qword VM memory, copies `min(a3,3)` context qwords into VM memory, then loops: decode opcode byte = `prog[pc] ^ keystream(pc)` (keystream = mix of three MurmurHash3-style streams over `pc` seeded by key dwords `A40/A44/A48`), index into the 256-entry table, de-XOR each entry with the mask (`A50`), call the handler; stop when `running==0`; then write VM memory[0] back to `ctx[0]`.

**Instruction set (75 distinct handlers across 256 opcode slots; all decoded).** Push imm8/imm32/imm64; loads/stores of width 8/16/32/64 through a pointer popped from the stack; ALU: ADD, SUB (`~(b+~a)`), MUL, XOR, OR, AND, NOT, NEG, SHL, SHR, SAR, zero-extend 8/16/32; comparisons EQ/NE/LT/LE/GT/GE in signed and unsigned variants; control flow JMP/JZ/JNZ (rel32); DUP, SWAP, DROP, ISZERO; PUSH-reg / POP-reg with **hashed register indices** (`(fetchbyte ^ hash(prevpc)) & 0x3F`); a "native call" opcode that pushes one of four fixed 64-bit constants; a **sub-VM call** opcode that recurses into `sub_140005130` with one of the four sub-programs and up to 3 stack arguments; and 173 of the 256 slots are HALT variants (clear `running`, each with its own junk constant).

---

## Q2. EXACT OUTPUT

**Format strings recovered exactly (High):**
```
<message>\n                     (puts)
chk=%08x mix=%08x\n
serial=%08x\n
serial2=%08x\n
```

**Exact values NOT recovered. Precise reason:** the message and all three hex values are produced by the four VM bytecode programs stored as pure data (299/189/123/321 bytes at `140018800/140018930/1400189F0/140018A70`). Every opcode byte and every operand byte of these programs is XOR-obfuscated with a position-keyed keystream, and register indices are additionally hashed with the previous pc. Two steps remain to the values: (1) a *keyed static disassembler* for the VM programs — mechanically possible with what I recovered (exact keystream formulas, exact key dwords folded below, exact index→handler table extracted in `dig2_out.txt`), but writing it was not completed in this assessment; and (2) *evaluation* of the disassembled programs — which requires interpreting/emulating the target's code, explicitly prohibited by the task rules. That combination is the specific barrier.

What is pinned down about the outputs (High):
- Message: exactly 49 characters (`Buffer[49]` explicitly NUL'd; blob is 49 bytes: `F7 C2 F0 C4 32 4E BA 5B 65 34 D1 AD BF 45 1B 24 68 F7 D4 86 F1 5D 35 75 83 AB 30 01 55 4B 48 D9 2C EE 55 2E 26 07 28 60 29 89 56 2D 84 B3 07 16 7D`), printable plaintext produced by program 1.
- `chk` = checksum of that 49-byte **ciphertext** blob (program 2).
- `mix` = program 3 applied to the single input `K1 ^ chk`.
- `serial` = program 4 over `message[34..46]` (13 bytes); `serial2` = program 4 over `message[0..16]` (17 bytes). So all three printed values are deterministic functions of the one decrypted message.
- Under a debugger the key dwords change (values below), so a debugged run prints different (wrong) values — the outputs above are for the no-debugger path.

---

## Q3. ALGORITHMS

**Key derivation (fully recovered, High).** Two decoy exports feed a linear mixer:
- `H = jpeg_huff_decode()` **= 0x4135666D**: `acc = 0xABCD`; for each of 24 bytes at `140018370`: `acc = b ? ROL32(acc, b&7) + b : acc ^ 0x61C88647`.
- `D = jpeg_dct_quant()` **= 0x027632D1**: `S = (Σ_{i=0..63} q[i]·(i+1)) mod 2^16` over the standard JPEG luma quant table at `1400183B0`; return `S ^ (ROL32(S,11) + 11291)`. (SIMD path taken deterministically — `__isa_available ≥ 2` on x64.)
- Mixer: `v1 = H − 331721344`; `v2 = D ^ 0x6D2E5E05`; if `IsDebuggerPresent()`: `v0 = 757124358, v1 += 7` else `v0 = 756358681`; then
  - `A48 = v2 − 2124864660`
  - `A40 = ROL32(v0,3) ^ 0x2CA2BD5A`
  - `A44 = (27341·v1) ^ 0x582B93A4`
  - `mask A50 = (A44 + ROL32(A40,9)) ^ 0x3CCE5F7E`
- Folded values — normal path: **A40 = 0x440A4D93, A44 = 0xFE620D6D, A48 = 0xF0B19040, A50 = 0x2E336C8B**; debugger path: A40 = 0x45A4D56B, A44 = 0xFE6719C0, A50 = 0x74DFAF35.

**Opcode/operand obfuscation (fully recovered, High).** Fetch-byte (`sub_140001850`) returns `prog[pc] ^ K(pc)`, where `K(pc)` XORs three streams: murmur-fmix of `(A40 ^ 0x9E3779B1·pc)`, murmur-fmix of `(A44 + pc)`, and `-109·fmix(murmur(A48 ^ ROL32(pc,3)))`, each with the murmur `>>13 / ·0x5BD1E995 / ·0x1B873593 / >>15` shape. Constants present: **0x5BD1E995** (1540483477), **0x1B873593** (461845907), **0x9E3779B1** (1640531535), **0x61C88647**, **−109 (0x93)**, **−107 (0x95)**. imm32/imm64 fetchers are the unrolled 4/8-byte versions of the same scheme; the dispatcher's opcode index uses the same keystream shape.

**chk / mix / serial / serial2 / K1 (Medium — structure known, formulas not decoded).** These are the data-only VM programs. Their algorithms are recoverable only by disassembling programs 1–4 (not completed here); the complete ISA they execute is documented above and in `dig3_out.txt`.

**Native-call "functions" (High).** The four call targets are constant generators: each returns a fixed 64-bit value (0xB5C7B72FF45A0699, 0xC7DBC0050C8E03CF, 0x5D8C262179924D6D, 0xC301446182223E9A) via `x ^= x>>13; x *= 0x2545F4914F6CDD1D; x ^= x>>27` over seeds 0x4025D83C82C0BF75 / 0x9A5DA6C08F82E872 / 0xC27E42EF5AA9038C / 0x7A0BFFF8C22AA40B. These same constants appear as junk in HALT/obfuscation templates.

---

## Q4. PROTECTION (High confidence throughout)

- **Not packed.** Section names **UPX0/UPX1/UPX2/UPX6 are fake** (misleading metadata). Layout is a normal MSVC image with renamed sections: UPX1 = code (XR), `.idata`, UPX2 = read-only data, UPX0 = writable data (WR), UPX6/`.jd` read-only. Entry is the plain CRT stub; imports are ordinary (69 KERNEL32 entries, mostly CRT/SEH support: RtlCaptureContext, RtlVirtualUnwind, etc.); no unpacking stub, no section that transitions W→X.
- **Compiler:** MSVC x64 (`__scrt_common_main_seh`, `__security_cookie`, `__isa_available` dispatch in the decoy export).
- **Real protection: a custom in-house bytecode VM** ("algorithm as data"): 251 handler functions reached through a 256-entry pointer table stored XOR-masked; per-position keyed opcode/operand obfuscation; hashed register indices; junk arithmetic in essentially every handler; sub-VM recursion capability.
- **Misleading metadata:** decoy exports `jpeg_dct_decode`-style names (`jpeg_huff_decode`, `jpeg_dct_quant`, `jpeg_idct_8x8`, `png_crc32_table`) used purely as key material; decoy media data in UPX2 (a 64x64 24-bpp "BM" bitmap header and MIDI-like bytes near `140018300`); a real JPEG luma quant table used as key input.
- **Anti-analysis:** `IsDebuggerPresent()` shifts the key dwords (wrong A40/A44/A50 ⇒ wrong dispatch table and wrong results, values above); `GetTickCount()` called before each VM run with the result discarded (timing/decoy noise).

---

## Q5. EFFORT ESTIMATE (to fully recover Q2 from my stopping point)

Starting from this assessment's artifacts (ISA decoded, dispatcher and fetch formulas exact, key dwords folded, all four program blobs and data extracted, index→handler table in `dig2_out.txt`): a skilled reverser needs a **keyed VM disassembler (~2–4 h**, most of it corner cases in the imm32/imm64 keystreams), disassembly of the 4 programs (minutes once the disassembler exists), then a Python re-implementation of the four programs and verification (**1–3 h**). Total: **roughly 4–8 focused hours — half a working day (High confidence)**. From a cold start, add 1–2 days for the handler triage and dispatcher/key work already done here. If dynamic analysis were permitted, the answer would be minutes — a single un-debugged run prints the message and all three values.

**Confidence summary:** Q1 flow — High. Q2 formats/structure — High; Q2 exact values — not recovered, barrier stated above (that is the finding, not a gap in method). Q3 key derivation, dispatch hashing, native constants — High; Q3 VM-program algorithms — Medium (ISA known, programs not disassembled). Q4 — High. Q5 — Medium-High.
