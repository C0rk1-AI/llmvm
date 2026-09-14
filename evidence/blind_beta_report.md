# Blind analyst report — sample_beta (PROTECTED exe, copy of demo_vm.exe)

Protocol: fresh-context agent (same model), static analysis only (no execution/emulation),
full idalib access + own scripts allowed, no knowledge of which sample was protected.
Verbatim deliverable below. Grading vs ground truth (message / chk=c0dfacd7 /
mix=321d16a7 / serial=3b158b09 / serial2=7d1cd601): W1 macro flow mostly correct
(one wrong inference: mix speculated ASLR-dependent — actually deterministic);
W2 FAILED (message and all four values unrecovered; own key arithmetic failed its
self-check); W3 protection-layer structure largely recovered but zero business
algorithms/constants; W4 not narrative-misled (saw through fake UPX + fake exports)
yet still blocked at content; W5 payload recovery = 0, estimated human handoff 4-12h to 2 days.

---

# Static reverse-engineering assessment: `sample_beta.exe`

## Scope and compliance

I performed static analysis only. I did not execute, debug, load, or emulate the target. IDA Pro 9.1/idalib was used to open the file, decompile functions, inspect xrefs, and read bytes. I also used ordinary Python arithmetic on bytes and constants already recovered from the binary; that did not execute or interpret target code.

Analysis artifacts created under the permitted directory:

- `..\blindtest\beta_report_top14.txt`
- `..\blindtest\beta_deep_static.txt`
- `..\blindtest\beta_deep_static.py`
- `..\blindtest\beta_table_static.py`
- `..\blindtest\beta_table_static.out`

---

# Q1. Program behavior

**Confidence: high for the control flow; medium for intended interpretation as a "protected message/checksum/serial demonstration."**

## High-level identity

- 64-bit Windows console executable.
- Preferred image base is `0x140000000`.
- Entrypoint/exported `start` is at VA `0x140006E60`.
- `start` calls `_security_init_cookie` and then the normal MSVC CRT startup path, `__scrt_common_main_seh`.
- The user function is:

  `main` at VA `0x140004F20`

- The binary contains a statically linked MSVC CRT, producing hundreds of noisy CRT functions. The relevant custom code lies mostly in `0x140001000` through `0x1400069CF`.

## Plain-language `main` flow

`main` has two adjacent output regions on its stack:

- `char Buffer[34]`
- `_BYTE v12[22]`

It performs four executions of a custom protected-program interpreter, represented here as P1–P4:

### 1. Decrypt/generate the message and associated secret data

`main` initializes a three-qword machine context with:

```text
register[0] = Buffer
register[1] = 0x1400182D0
register[2] = 49
```

It then runs protected program P1:

- Code blob: `0x140018800`
- Encoded length: 299 bytes
- Initial-context copy count: 3 qwords
- Dispatcher setup: `sub_140005330`
- Interpreter: `sub_140005130`

P1 is the program that populates `Buffer` and, based on the later use of `v12`, also populates data used by the native serial wrapper.

After P1, `main` explicitly sets:

```text
v12[15] = 0
```

and prints:

```c
puts(Buffer);
```

Therefore the first output line is a decrypted/generated NUL-terminated string.

### 2. Compute `chk`

`main` initializes a second context:

```text
register[0] = 0x1400182D0
register[1] = 49
register[2] = 0
```

It runs P2:

- Code blob: `0x140018930`
- Length: 189 bytes
- Context copy count: 2

After P2, it takes the low 32 bits of the first machine register:

```text
chk = low32(P2.register[0])
```

### 3. Compute `mix`

`main` initializes an input qword as:

```text
v6 = low32(post-P1 register[0]) XOR chk
```

and zeros the adjacent machine registers.

It runs P3:

- Code blob: `0x1400189F0`
- Length: 123 bytes
- Context copy count: 1

The resulting `mix` is the low 32 bits of the first qword of the P3 context.

It then prints:

```text
chk=%08x mix=%08x\n
```

### 4. Compute `serial`

`main` calls:

```c
sub_140006960(v12, 13)
```

`sub_140006960` at `0x140006960` is not itself the serial algorithm. It is a wrapper that:

1. Creates a machine context:

   ```text
   register[0] = v12
   register[1] = 13
   register[2] = 0
   ```

2. Runs P4:
   - Code blob: `0x140018A70`
   - Length: 321 bytes
   - Context copy count: 2

3. Returns the low 32 bits of the first machine register.

Thus:

```text
serial = P4(input=v12, length=13)
```

### 5. Compute `serial2`

`main` then initializes a new context:

```text
register[0] = Buffer
register[1] = 17
register[2] = 0
```

and runs the same P4 program again:

```text
serial2 = P4(input=Buffer, length=17)
```

It prints:

```text
serial2=%08x\n
```

Finally, `main` returns zero.

## Interpreter architecture

`sub_140005130` at `0x140005130` is a custom bytecode VM/interpreter.

Its machine-state layout, recovered from handler accesses, is:

| Offset | Purpose |
|---:|---|
| `+0x000` | current code pointer |
| `+0x008` | current program counter |
| `+0x00C` | executed-instruction counter |
| `+0x010` | stack-base sentinel |
| `+0x018` | stack cell 0 |
| `+0x818` | stack pointer, 2072 decimal |
| `+0x820` | 64-qword register file, 2080 decimal |
| `+0xA20` | run flag, 2592 decimal |

The interpreter:

1. Clears 64 qwords of registers.
2. Copies the first 1, 2, or 3 qwords from the caller's context into registers.
3. Repeatedly decodes one opcode byte and calls an indirect handler.
4. Copies register 0 back to the caller's context when the run flag clears.

The handler table is exactly 256 qword entries at:

```text
0x140023A60 through 0x140024258
```

I extracted all 256 initializer assignments with no missing entries.

Handler examples observed:

- `sub_140002B70`: comparison/test-style stack operation.
- `sub_140002BE0`: greater-or-equal comparison.
- `sub_1400045D0`: conditional relative branch. It decodes a signed 32-bit immediate with `sub_140001180` and conditionally adds it to the VM PC.
- `sub_140001180`: four-byte operand decoder.
- `sub_1400014C0`: a wide operand decoder processing ten encoded bytes into a 64-bit value.
- `sub_140001850`: one-byte operand decoder.
- Numerous handlers are ordinary stack/register operations.
- A class of 32-byte handlers clears the run flag, clears the stack pointer, and XORs register 0 with a constant; these are terminal/reset-style handlers.

## End-to-end interpretation

This is an output-only protected demonstration program. It:

1. Decrypts or generates a secret message.
2. Computes a checksum-like value.
3. Computes a mixed value.
4. Computes two serial/hash-like values.
5. Prints all four values.

I found no evidence in `main` or the relevant custom code of network activity, file creation, persistence, command parsing, or user interaction.

---

# Q2. Exact output

**Confidence: high for the exact output structure; low/failed for the exact decrypted message and numeric values.**

## Exact output shape

The program would produce exactly this four-line structure:

```text
<decrypted or generated message>
chk=xxxxxxxx mix=xxxxxxxx
serial=xxxxxxxx
serial2=xxxxxxxx
```

All numeric fields are lowercase hexadecimal because the format strings use `%08x`.

Observed format strings:

- At VA `0x140018BB8`:

  ```text
  chk=%08x mix=%08x\n
  ```

- Also present in the string table:

  ```text
  serial=%08x\n
  serial2=%08x\n
  ```

`puts(Buffer)` adds its own newline after the message.

## Message length clue

The second execution of P4 explicitly sets the input length for `Buffer` to 17. This strongly suggests that the generated message region is intended to be 17 bytes, likely 16 payload bytes plus a NUL terminator, although `puts` ultimately stops at the first NUL wherever it appears.

The first serial input is exactly 13 bytes from `v12`.

## Exact values not recovered

I could not responsibly recover the exact message, `chk`, `mix`, `serial`, or `serial2` in this pass. The reason is specific: full decoding of the custom VM bytecode was not completed, and my derived opcode-decryption seed set did not pass a structural consistency check.

### What was recovered

The four encrypted program blobs are fully identified:

| Program | VA | Length | Use |
|---|---:|---:|---|
| P1 | `0x140018800` | 299 | message/secret generation |
| P2 | `0x140018930` | 189 | checksum |
| P3 | `0x1400189F0` | 123 | mix |
| P4 | `0x140018A70` | 321 | both serial and serial2 |

The handler dispatch table was fully extracted:

- 256 entries.
- No missing entries.
- No conflicting assignments.

The interpreter's state layout and several handler semantics were recovered.

### Specific barrier

The initializer derives runtime seeds from two misleadingly named export routines. My arithmetic on their decompiled logic and static data gave a candidate normal-domain key of:

```text
qword_140023A50 = 0x2E336C8B
```

However, applying my reconstructed opcode formula to the first P1 byte selected a handler that immediately clears the VM run flag. That is inconsistent with the rest of the program and with the ciphertext structure.

In particular, P1 and P2 begin:

```text
P1: c6 27 f7 4a 47 63 70 2a 72 33 ...
P2: c6 7d da a2 dd 63 70 2a 72 33 ...
```

The bytes at PC positions 0 and 5–9 match, while positions 1–4 differ. This is strong evidence that the first instruction is one opcode plus a four-byte encoded immediate, followed by the same opcode at PC 5. A run-flag-clearing first handler cannot be correct.

Therefore one of the following remains unresolved:

- a mistake in my arithmetic for one of the seed functions;
- a subtlety in the exported seed routine;
- a transcription error in the dispatch formula;
- an additional key/table transformation not yet recognized;
- or an incorrect assumption about the no-debugger seed domain.

Without a validated dispatch stream, the operand bytes cannot be separated from opcode bytes, and the four programs cannot be lifted or evaluated.

## Possible Lack of one fixed `mix` value

`mix` is initialized from:

```text
low32(post-P1 register[0]) XOR chk
```

The first P1 context begins with `register[0] = Buffer`, a stack address. If P1 leaves that register as the output pointer, as appears likely, `mix` incorporates the low 32 bits of a stack address and will vary between processes/runs under ASLR and differing stack conditions.

Thus there may be no single universal `mix` value even after the VM is decoded. The code's exact use of `LODWORD(v10[0])` is direct evidence; only complete P1 register recovery would settle whether that register remains a pointer or is overwritten with a deterministic value.

---

# Q3. Algorithms and constants

**Confidence: high for the VM/obfuscation algorithms; medium for my numeric seed/key arithmetic; low for the high-level checksum/serial algorithms because they exist primarily as protected VM bytecode.**

## Initialization/key derivation

The one-time initializer is:

```text
sub_140005330 at 0x140005330
```

It is guarded by `dword_1400242C0`.

It calls two misleading export routines:

- `jpeg_huff_decode` at `0x140001920`
- `jpeg_dct_quant` at `0x140001AE0`

Then:

```text
A48 = jpeg_dct_quant() XOR 0x6D2E5E05 - 2124864660
A40 = ROL32(seed0, 3) XOR 0x2CA2BD5A
A44 = (27341 * (jpeg_huff_decode() - 331721344)) XOR 0x582B93A4

key = uint32(A44 + ROL32(A40, 9)) XOR 0x3CCE5F7E
qword_140023A50 = key
```

The debugger-sensitive values are:

| Condition | `seed0` | huff-derived adjustment |
|---|---:|---|
| no debugger | 756358681 | none |
| `IsDebuggerPresent()` | 757124358 | `+7` before scaling |

My arithmetic produced the following candidate values.

### Normal, no debugger

```text
jpeg_huff_decode result      = 0x4135666D
after -331721344             = 0x2D6FBBED
weighted-table accumulator   = 0x00024ECA
low 16 bits                  = 0x00004ECA
jpeg_dct_quant result        = 0x027632D1

A40 = dword_140023A40        = 0x440A4D93
A44 = dword_140023A44        = 0xFE620D6D
A48 = dword_140023A48        = 0xF0B19040
ROL32(A40, 9)                = 0x149B2688
candidate key                = 0x2E336C8B
```

### Debugger-present domain

```text
A40 = 0x45A4D56B
A44 = 0xFE6719C0
candidate key = 0x74DFAF35
```

These numeric values should be treated as **medium confidence** because of the first-opcode inconsistency described in Q2. The formulas themselves are high-confidence direct Hex-Rays output.

## Export seed routines

### `jpeg_huff_decode`

Despite its name, it is not JPEG Huffman decoding. It:

1. Starts with accumulator `0xABCD`.
2. Processes 24 static bytes around VA `0x140018370`–`0x140018387`.
3. For each byte:
   - if nonzero, rotates the accumulator by `byte & 7`, then adds the byte;
   - if zero, XORs with `0x61C88647`.

### `jpeg_dct_quant`

It is also not DCT/quantization. It computes a weighted sum over 64 bytes at VA `0x1400183B0`:

```text
sum = Σ (i + 1) * table[i], for i = 0..63
v = low16(sum)
result = v XOR ((ROL32(v, 11) + 11291) mod 2^32)
```

My observed weighted sum was:

```text
sum = 151242 = 0x24ECA
```

The routine has a SIMD path and scalar fallback, but both represent the same weighted-sum construction.

The other named exports are outright constant stubs:

- `jpeg_idct_8x8` returns `3963245952`.
- `png_crc32_table` returns `3469664904`.

## Handler-pointer obfuscation

The initializer fills the 256-entry handler table using:

```text
table[i] = native_handler_address XOR key
```

At dispatch time, the interpreter computes:

```text
actual_handler = qword_140023A50 XOR table[i]
```

The blob-pointer records at `0x140024280`, `0x140024290`, `0x1400242A0`, and `0x1400242B0` use the same construction:

```text
stored_blob_pointer = actual_blob_address XOR key
```

Therefore `main` obtains the actual code address by XORing with `qword_140023A50`.

## Opcode-byte decryption

The dispatcher uses a MurmurHash3-finalizer-like family with these constants:

```text
C1 = 1540483477 = 0x85EBCA6B
C2 = 461845907  = 0xC2B2AE35
delta = 0x9E3779B9
```

For a program counter `P` and encoded opcode byte `cipher[P]`:

```text
x0 = A40 XOR (0x9E3779B9 * P)
h0 = C2 * ((C1 * (x0 XOR (x0 >> 13))) XOR (... >> 15))

x1 = A44 + P
h1 = C2 * ((C1 * (x1 XOR (x1 >> 13))) XOR (... >> 15))

r = ROL32(P, 3)
x2 = A48 XOR r
m2 = C1 * (x2 XOR (x2 >> 13))
f2 = C2 * (m2 XOR (m2 >> 15))

index = low8(
    (-109 * (m2 XOR (m2 >> 15)))
    XOR h1
    XOR h0
    XOR cipher[P]
    XOR low8(h0 >> 13)
    XOR low8(h1 >> 13)
    XOR low8(f2 >> 13)
)
```

It then increments the PC and invokes:

```text
handler = qword_140023A50 XOR qword_140023A60[index]
```

Operands are separately encrypted using related keyed transformations in `sub_140001180`, `sub_1400014C0`, and `sub_140001850`.

## High-level computed values

The exact mapping is:

```text
chk     = low32(P2 output register 0)
mix     = low32(P3 output register 0)
serial  = low32(P4(v12, length=13) output register 0)
serial2 = low32(P4(Buffer, length=17) output register 0)
```

The high-level checksum, mix, and serial algorithms are not present as ordinary native loops. They are encoded in P2, P3, and P4. Therefore their algorithm descriptions require full bytecode lifting, which was not completed.

---

# Q4. Protection, packing, and misleading metadata

**Confidence: high for custom VM protection and misleading export metadata; medium for the conclusion that the UPX section names are deliberately fake rather than remnants of an actual UPX pack.**

## Custom virtualization/obfuscation

This binary is protected by a custom bytecode VM and pointer-obfuscation scheme:

- 256-entry indirect handler table.
- Hundreds of small native handler routines.
- Encrypted program blobs.
- PC-dependent opcode keystream.
- Separate keyed immediate/operand decoding.
- XOR-obfuscated code pointers and handler pointers.
- One-time runtime initialization.
- Debugger-sensitive key domain.
- A large amount of duplicated/simple handler noise.

This is the primary protection, not conventional section compression.

## Misleading export names

The PE exports are deliberately deceptive:

```text
jpeg_dct_quant
jpeg_huff_decode
jpeg_idct_8x8
png_crc32_table
```

Their actual behavior is:

- two custom seed-derivation routines;
- two constant-returning stubs.

They do not implement the image-processing algorithms their names suggest.

The static data near `0x140018300` also contains a fake `BM` header and image-like fields/tables, reinforcing the decoy theme.

## Anti-debugging

`sub_140005330` directly imports and calls `IsDebuggerPresent`.

If a debugger is present:

- one seed changes;
- the huff-derived seed gets `+7`;
- the entire key changes;
- consequently the handler table, blob-pointer decoding, and opcode stream decode differently.

This is a real anti-debug/key-domain branch, not merely a named import.

The repeated unused `GetTickCount()` calls in `main` and the serial wrapper are likely timing/anti-emulation decoys; I did not observe their return values being used in the decompiled relevant paths.

## UPX section names

IDA reported sections including:

```text
UPX1
UPX2
UPX0
UPX6
```

However:

- the entrypoint reaches the normal CRT startup path;
- `main`, the CRT, imports, strings, handler functions, and data blobs are directly visible;
- no operational UPX unpacking stub was identified in the analyzed flow;
- the sample is fully amenable to ordinary static decompilation.

Therefore the UPX-like names are misleading metadata. They may be deliberately forged section names or manipulated remnants, but they do not describe the effective protection seen in the analyzed code. I found no evidence of VMProtect, Themida, or another commercial virtualizer signature; the VM appears custom.

---

# Q5. Effort estimate to finish Q2

**Confidence: medium.**

Starting from the current state—not from zero—the remaining work is well bounded:

1. Resolve/validate the seed and opcode-decoding inconsistency.
2. Confirm the exact 256-entry handler map against native disassembly.
3. Classify the unique handler semantics; many are duplicates or trivial stack/register operations.
4. Recover operand lengths and operand decoding.
5. Produce a small lifter or external Python model of the VM.
6. Decode P1–P4 and evaluate them for the two P4 input contexts.

A skilled reverse engineer with IDA and scripting experience would likely need:

- **4–12 hours** if the current key discrepancy is a small transcription/seed error and the handler semantics are as regular as they appear.
- **1–2 working days** is a more conservative estimate, allowing time to classify all unique handlers and write a reliable lifter/emulation model.
- Starting from zero without the current handler table and state-layout notes would likely take several days to about two weeks.

Recovering only the decrypted message might take approximately **2–6 hours** after the dispatch key is corrected, because P1 can be followed independently of fully understanding all four programs.

The important unfinished technical barrier is not data availability—all four blobs are extracted and readable—but validated devirtualization of the custom opcode and operand encoding.
