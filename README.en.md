# LLMVM — A Code Virtualization Protector Against AI-Powered Reverse Engineering

**English | [简体中文](README.md)**

## Overview

Traditional packers and VM protectors are designed against a human analyst.
LLMVM targets a different adversary: LLM agents that do static reverse
engineering through front ends such as IDA and Ghidra. These agents read
decompiled pseudocode quickly, anchor on strings and constants to find key
code, and walk cross-references to map the call graph. They also work within
a limited context window and can be led astray by conclusions that merely
look plausible.

LLMVM exploits these traits in three ways:

- The real code exists only as encrypted bytecode. Its keys are assembled at
  runtime from the return values of decoy functions, so no static method can
  read the code.
- Every build injects roughly 130 thematically consistent decoy strings and a
  full set of fake metadata (section names, export names, PDB path), leading
  the analysis toward a wrong program identity.
- More than 200 polymorphic handlers, aliased opcodes, dead code, and decoy
  functions inflate the context and computation an analysis has to spend.

LLMVM does not claim the protected code is unrecoverable. What it raises is
the cost and the error rate of an attack. The full design, including a
mapping of 11 LLM failure modes to countermeasures, is in
[DESIGN.md](DESIGN.md).

## How It Works

```
vm_targets.c (subset-C source)
        │  vmc.py
        ▼
protected.c (VM interpreter + wrappers + decoy functions)
        │  MSVC cl
        ▼
       exe ──pepolish──▶ final.exe

same logic in plain C ──MSVC cl──▶ plain.exe (control group)
```

Target functions are compiled into encrypted bytecode for a custom
stack-based virtual machine. The file contains only ciphertext; the keys are
assembled at runtime from the return values of decoy functions. The
interpreter is built from 200+ handlers whose machine code differs on every
build, and every function table is XOR-masked.

Each build also produces an unprotected native binary (`plain.exe`) as a
control. The two programs must produce byte-identical stdout, or the build
fails. `run_demo.py` and `run_selftest.py` run this comparison automatically.

## Requirements

- Windows x64 + MSVC (VS2017 / 2019 / 2022, or the standalone Build Tools
  with the C++ desktop workload). The toolchain is located automatically:
  `LLVMVM_VCVARS` env var, then `cl` already on PATH (a VS developer
  prompt), then vswhere, then common install paths. If none is found, the
  build stops with a message pointing at `LLVMVM_VCVARS`.
- Python 3.10+, standard library only.
- Optional: IDA Pro 9.1 + idalib, for reproducing the validation reports:

  ```bash
  pip install "C:\Program Files\IDA Professional 9.1\idalib\python"
  python "C:\Program Files\IDA Professional 9.1\idalib\python\py-activate-idalib.py"
  ```

## Quick Start

```bash
# Demo: build the native control and the VM-protected binary (with pepolish
# and fake exports), run both, and diff the output
python run_demo.py

# Semantic-equivalence regression: batch-build VM / native pairs across
# random seeds; outputs must match byte for byte
python run_selftest.py

# Handler template identity tests (35 polymorphic templates over large
# random input sweeps; 0 mismatches passes)
python tools_tpl_test.py

# Generate an IDA analysis report for any exe (reproduces the validation
# experiments in REPORT.md)
python tools_ida.py evidence/sample_alpha.exe my_report.txt 14

# Fold the ground-truth keys and check build determinism
# (seed in evidence/seed.txt)
python evidence/fold_true_key.py

# v3 inner-program differential audit: every inner program vs native
# semantics, 0 mismatches passes
python evidence/inner_audit.py <seed>
```

## Protecting Your Own Code

1. Write the functions to protect in one subset-C source file. The language
   supports:

   - types: int8..int64 / uint8..uint64, `float` / `double`, pointers;
   - data: 1-D and multi-dimensional arrays (global and local), structs
     (nesting, array members, `.` / `->` member access);
   - control flow: if / else, for / while, break / continue;
   - operators: arithmetic / bitwise / comparison, with the usual implicit
     conversions between int and float;
   - functions: mutual calls, recursion (direct, or mutual via forward
     declarations), variadics.

   Library functions cannot be called directly. Register host functions such
   as puts and printf in `host_config.py` first; float-typed parameters and
   return values are declared with the `'sig'` field, e.g.
   `'sqrt': {'arity': 1, 'sig': 'd', 'ret': 'd'}`.

   A few conventions:

   - Structs follow MSVC default alignment. Across function boundaries they
     are pointer-only: by-value parameters and returns and whole-struct
     assignment are not supported.
   - Local arrays and local structs live in per-invocation frame storage,
     capped at 512 bytes per function; recursion is safe.
   - Declare variadic functions as `uint64_t vsum(uint64_t nv, ...)`: at
     most 3 fixed parameters, the last one must be named `nv` and holds the
     vararg count (up to 32 per call). The function body begins with
     `vv_start();`; each `vv_next()` returns the next vararg as a raw u64
     slot: float varargs are already promoted to double bit patterns at the
     call site, and narrow integers are sign-extended. Pass 64-bit literals
     at call sites (e.g. `10ull`). The native control reads varargs with
     `va_arg(ap, uint64_t)`, and the upper bytes of 32-bit literals are
     undefined under the MSVC variadic ABI.

   See `demo/vm_targets.c` and `tests/selftest_targets.c` for working
   examples.

2. Keep `main` in its own file (`--main`). The generator rewrites its calls
   to the protected functions as VM wrappers.
3. Generate, compile, and disguise:

```bash
python vmc.py build --targets my/targets.c --host my/host_config.py \
                    --main my/main.c --outdir out --seed 12345
cl ... out\protected.c            # wrapped by vmlib/build.py's build_exe()
python pepolish.py final.exe      # renames sections to UPX*, appends a decoy-laden .jd section
```

Changing `--seed` regenerates the opcode numbers and aliases, the handler
machine-code shapes, the keys and decoy constants, the encryption formulas,
the KSET re-keying scheme, and the decoy themes and string combinations. Two
builds of the same source share no reusable static signature.

## Protection Mechanisms

The table groups the mechanisms by the analysis behavior they target; see
[DESIGN.md](DESIGN.md) §1–2 for details. "Per build" below means changing
the `--seed` regenerates the right-hand column.

| Analysis behavior | Countermeasure |
|---|---|
| Anchoring on strings to locate key code (the most common path) | Real strings and constants exist only as ciphertext in the bytecode stream |
| Inferring program identity from section / export names and PDB paths | Each build draws a fake identity from 18 themes (UPX, VMProtect, NSIS, sqlite, libpng, games, drivers, ...; two-theme mixes allowed), with ~130 matching decoy strings |
| Fingerprinting algorithms by constants (MD5 init values, CRC32 polynomials) | Decoys deliberately plant standard fingerprint constants, steering the analysis toward the fake narrative |
| Reasoning over decompiled pseudocode | Every semantic op gets a fresh machine-code template per build; 200+ anonymous handlers keep the pseudocode unreadable |
| Walking the call graph via call / xref | Dispatch, host, and VM function tables are all XOR-masked, so static call targets do not resolve |
| Limited context window | Handler count, aliased opcodes, dead code, and decoy functions (never fewer than the real ones) inflate the analysis |
| Self-written decryption / evaluation scripts | Encryption formulas are randomized per build; KSET layered re-keying at every function entry forces a script to parse the variable-length instruction stream and evaluate the prologue arithmetic before it gets past the first layer; never-executed junk blocks poison pattern matching |
| Semantic lifting plus a hand-built emulator (the strongest attack from the v2 blind test) | v3 VM-in-VM: the load-bearing handlers are themselves another layer of encrypted bytecode, leaving no verifiable intermediate artifact between the two lifts |
| Debugger attachment | IsDebuggerPresent is XORed into the key material: attaching a debugger changes the keys, the bytecode decodes to garbage, and the program silently runs wrong logic |

## Validation

Validation has four parts, documented in full in [REPORT.md](REPORT.md):

1. Behavioral-equivalence regression: VM and native builds are batch-built
   across random seeds and their outputs must match byte for byte
   (`run_selftest.py`).
2. Author-side recovery attempts: real recovery work against the protected
   binaries with idalib (IDA 9.1's headless analysis library), to measure
   what the artifacts actually leak.
3. Blind tests with uninformed agents: sub-agents of the same model, unaware
   of this project's design, analyze the protected and control samples and
   are scored on five criteria (entry-point identification, string recovery,
   algorithm recovery, decoy misjudgement, overall verdict). The control
   group was fully recovered, which validates the method; every protected
   group was misled by the decoys.
4. Anti-script attacks: the v2 / v3 blind-test rounds explicitly allow and
   encourage pure-static attacks with self-written decryption and emulation
   scripts, testing the anti-script mechanisms directly.

The experiments and blind tests ran on the same attack shape LLMVM defends
against: Claude Code driving the GLM-5.3 model, with IDA accessed through
idalib MCP tools.

Samples, ground-truth keys, and review scripts for every round are archived
under [evidence/](evidence/). v3 (VM-in-VM, denormalization, formula
variants, metadata scrubbing) targets the strongest attack path found in the
v2 blind test; see [DESIGN.md](DESIGN.md) §2b for the mechanisms and
[REPORT.md](REPORT.md) §6 for the retest.

## Known Limitations

- The threat model covers static LLM analysis only. Dynamic debugging
  (patching keys after attachment), Unicorn emulation, symbolic execution,
  and a human expert classifying every handler via IDAPython still work;
  LLMVM raises cost and error rate, not unbreakability.
- Language: structs cross function boundaries by pointer only (no by-value
  parameters or returns, no whole-struct assignment), and there is no
  switch or function-pointer support; protected code reaches the outside
  world only through registered host functions.
- The build needs MSVC `cl` and emits C source; direct PE input is not
  supported yet.
- Some antivirus products flag freshly built obfuscated executables; retry
  with a different seed (run_demo / run_selftest include retries and
  randomized build directories).

## License

MIT, see [LICENSE](LICENSE). The executables under `evidence/` are
experiment samples with decoy strings and disguised section names; they are
for reproducing the static analysis only. Do not run them.
