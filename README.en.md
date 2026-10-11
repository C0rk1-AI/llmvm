# LLMVM — A Code Virtualization Protector Against AI-Powered Reverse Engineering

**English | [简体中文](README.md)**

## Overview

Traditional packers and VM protectors assume a human adversary. LLMVM shifts the threat model toward **LLM-based automated static reverse engineering** — AI agents that analyze binaries through an IDA / Hex-Rays front end.

LLMVM does not claim information-theoretic unrecoverability. Instead, it exploits how LLM static analysis actually works to erect systematic disruption and cost barriers:

- **Conclusion steering**: each build injects ~130 thematically coherent decoy strings and a complete set of fake metadata, leading the analysis toward an incorrect program identity and functional narrative;
- **Information hiding**: the real code exists only as per-build randomized encrypted bytecode whose keys are assembled at runtime from decoy functions, invisible to static analysis;
- **Cost barriers**: polymorphic handlers, aliased opcodes, dead code, and decoy functions jointly inflate the context and computation an analysis must spend.

The full design — a mapping of 11 LLM failure modes to countermeasures — is documented in [DESIGN.md](DESIGN.md).

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

LLMVM compiles the target functions into encrypted bytecode for a custom stack-based virtual machine: on disk the bytecode is pure ciphertext, and the keys are assembled only at runtime from the return values of decoy functions. The interpreter consists of 200+ polymorphic handlers whose machine-code form differs on every build, and every function table is XOR-masked.

Correctness criterion: the build also produces an unprotected native version (`plain.exe`) as a control group, and the two programs' stdout must match byte for byte. `run_demo.py` and `run_selftest.py` perform this comparison automatically; any mismatch fails the build.

## Requirements

- Windows x64 + VS2017 (MSVC 14.16). The default path is `D:\VS17`; if yours is
  installed elsewhere, set the environment variable `LLMVM_VCVARS` to point at
  your `vcvars64.bat`.
- Python 3.10+ (pure standard library, no third-party dependencies).
- (Optional) IDA Pro 9.1 + idalib, for reproducing the validation reports:

  ```bash
  pip install "C:\Program Files\IDA Professional 9.1\idalib\python"
  python "C:\Program Files\IDA Professional 9.1\idalib\python\py-activate-idalib.py"
  ```

## Quick Start

```bash
# 1. Demo: build the native control group and the VM-protected version
#    (with pepolish and fake exports), run both, and diff automatically
python run_demo.py

# 2. Semantic-equivalence regression: batch-build VM / native pairs across
#    random seeds; outputs must match byte for byte
python run_selftest.py

# 3. Handler template identity tests (30 polymorphic templates x large
#    random input sweeps; 0 mismatches = pass)
python tools_tpl_test.py

# 4. Generate an IDA analysis report for any exe (reproduces the
#    validation experiments in REPORT.md)
python tools_ida.py evidence/sample_alpha.exe my_report.txt 14

# 5. Fold the ground-truth keys and verify build determinism
#    (seed in evidence/seed.txt)
python evidence/fold_true_key.py

# 6. v3 inner-program differential audit: every inner program from a real
#    build vs. native semantics (0 mismatches = pass)
python evidence/inner_audit.py <seed>
```

## Protecting Your Own Code

1. Write the functions to protect in a subset-C source file. Supported: int8..int64 /
   uint8..uint64, pointers, 1-D arrays, if/else, for/while, break/continue,
   arithmetic / bitwise / comparison operators, and function calls. Not supported:
   structs, floats, multi-dimensional arrays, recursion, varargs. Library functions
   cannot be called directly; host functions (e.g. puts/printf) must be registered
   explicitly in `host_config.py`. Working examples: `demo/vm_targets.c`,
   `tests/selftest_targets.c`.
2. Put the `main` entry point in a separate file (`--main`). The generator rewrites
   its calls to the protected functions into VM wrappers.
3. Generate, compile, and disguise:

```bash
python vmc.py build --targets my/targets.c --host my/host_config.py \
                    --main my/main.c --outdir out --seed 12345
cl ... out\protected.c            # vmlib/build.py's build_exe() wraps this step
python pepolish.py final.exe      # renames sections to UPX*, appends a decoy-laden .jd section
```

Changing the `--seed` regenerates everything: opcode numbers and aliases, handler
machine-code shapes, keys and decoy constants, encryption formula families, KSET
re-keying schemes, and decoy narrative themes and string combinations — no two
builds of the same source share any reusable static signature.

## Protection Mechanisms

Full details in [DESIGN.md](DESIGN.md) §1–2. "Per build" below means: changing the
`--seed` regenerates the entire right-hand column.

| LLM analysis behavior it defeats | Countermeasure |
|---|---|
| Anchoring on strings to locate key code (the most heavily used analysis path) | Real strings and constants exist only as ciphertext inside the bytecode stream — statically invisible |
| Inferring program identity from section / export names and PDB paths | Each build draws a disguised identity from 18 themes (UPX, VMProtect, NSIS, sqlite, libpng, games, drivers, …; two-theme mixes supported): section names, export names, PDB path, and ~130 thematically coherent decoy strings |
| Constant fingerprinting (MD5 init values, CRC32 polynomials, …) | Decoys deliberately plant standard fingerprint constants, steering inductive analysis toward the fake narrative |
| Semantic reasoning over decompiled pseudocode | The same semantic op gets a different machine-code template on every build; 200+ anonymous handlers render the pseudocode unreadable |
| Traversing the call graph via call / xref | Dispatch, host, and VM function tables are all XOR-masked; static call targets do not resolve |
| Context budget constraints | Handler count, aliased opcodes, dead code, and decoy functions (at least as numerous as real ones) jointly inflate analysis cost |
| Self-written decryption / evaluation scripts | Encryption formula families are randomized per build; per-function KSET layered re-keying forces any script to first parse the variable-length instruction stream and evaluate the prologue arithmetic before passing the first layer; never-executed junk blocks further poison pattern matching |
| Semantic lifting + hand-built emulators (the strongest attack, demonstrated in the v2 blind test) | v3 VM-in-VM: load-bearing handlers are themselves another layer of encrypted bytecode programs — no verifiable intermediate artifact exists between the two lifts |
| Debugger attachment | IsDebuggerPresent is XORed into the key material: attaching a debugger changes the keys, the bytecode decodes to garbage, and the program silently executes wrong logic |

## Validation

Effectiveness is assessed through a four-part protocol (full records in [REPORT.md](REPORT.md)):

1. **Behavioral-equivalence regression**: VM and native versions are batch-built
   across random seeds; outputs must match byte for byte (`run_selftest.py`).
2. **Author-side recovery experiments**: genuine recovery attempts against the
   protected executables using idalib (IDA 9.1's headless analysis library), to
   gauge how much information the artifacts actually leak.
3. **Blind tests with uninformed agents**: sub-agents of the same model, given no
   knowledge of this project, analyze the protected and control samples and are
   scored on five criteria (entry-point identification, string recovery,
   algorithm recovery, decoy misjudgement, overall verdict). The control group was
   fully recovered — validating the method — while every protected group was
   misled by the decoys.
4. The v2 / v3 blind-test rounds **explicitly permit and encourage** pure-static
   attacks using self-written decryption and emulation scripts, directly testing
   the anti-script mechanisms.

Blind-test samples, ground-truth keys, and review scripts for every round are
archived in [evidence/](evidence/). v3 (VM-in-VM, denormalization, formula
variants, metadata scrubbing) targets the strongest attack path identified in the
v2 blind test; see [DESIGN.md](DESIGN.md) §2b for the mechanisms and
[REPORT.md](REPORT.md) §6 for the retest.

## Known Limitations

- The threat model is restricted to **static LLM analysis**. Dynamic debugging
  (patching keys after attachment), Unicorn emulation, symbolic execution, and
  human experts performing full handler classification via IDAPython can still
  recover the semantics — LLMVM raises attack cost and error rate, not
  information-theoretic unrecoverability.
- Language restrictions: subset-C does not support floats, structs,
  multi-dimensional arrays, or recursion; protected functions interact with the
  outside world only through registered host functions.
- The build depends on MSVC `cl`: code generation emits C source; direct PE
  ingestion is not yet supported.
- Third-party antivirus software may flag freshly built obfuscated executables;
  retrying with a different seed resolves this (run_demo / run_selftest include
  built-in retries and randomized directories).

## License

MIT — see [LICENSE](LICENSE). The executables under `evidence/` are experiment
samples (they contain decoy strings and disguised section names); they are
provided for reproducing the static analysis only — do not execute them.
