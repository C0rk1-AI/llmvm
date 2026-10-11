# LLMVM — A Code Virtualizer Targeting LLM Static Analysis

**English | [简体中文](README.md)**

## What is this

Most packers and VM protectors are built to defeat a *human* — a reverse engineer sitting in front of IDA. LLMVM targets a different adversary: **an LLM statically analyzing your binary with IDA / Hex-Rays** (e.g. the growing crop of LLM-based automated reverse-engineering / auditing agents).

The goal is not to make the program "unrecoverable forever". It is to make sure that when an LLM analyzes the protected program, it either:

- gets led astray by 130+ convincing decoy strings and a complete fake identity, drawing wrong conclusions, or
- runs out of context budget / cost before it ever reaches the real code.

An analogy: before protection, the LLM sees a clean page of decompiled pseudocode. After protection, it sees a thick book in which every page is locked with a different cipher and dozens of pages are pure disinformation — and every time a new copy is printed, all the ciphers and all the fake pages are regenerated.

The full design (a mapping table of 11 LLM failure modes → countermeasures) is in [DESIGN.md](DESIGN.md).

## How it works

```
vm_targets.c (subset-C source)
        │  vmc.py compiles
        ▼
protected.c (VM interpreter + wrappers + decoy functions)
        │  MSVC cl
        ▼
       exe ──pepolish disguise──▶ final.exe

same logic in plain C ──MSVC cl──▶ plain.exe (control group)
```

The core idea in one sentence: **compile the functions you want to protect into encrypted bytecode for a custom stack-based VM**. On disk the bytecode is pure ciphertext; the keys only materialize at runtime, assembled from the return values of a few decoy functions that look like dead code. The interpreter itself is 200+ anonymous little functions that look different on every build, and every function table is scrambled with XOR masks.

How do you know the protection didn't break the program? The build also produces an **unprotected native version** (`plain.exe`) as a control group, and the two programs' stdout must be **byte-identical** — `run_demo.py` / `run_selftest.py` diff them automatically; any mismatch is an outright failure.

## Requirements

- Windows x64 + VS2017 (MSVC 14.16). The default path is `D:\VS17`; if yours lives
  elsewhere, set the environment variable `LLMVM_VCVARS` to point at your
  `vcvars64.bat`.
- Python 3.10+ (pure standard library, no third-party dependencies).
- (Optional) IDA Pro 9.1 + idalib, for reproducing the validation reports:

  ```bash
  pip install "C:\Program Files\IDA Professional 9.1\idalib\python"
  python "C:\Program Files\IDA Professional 9.1\idalib\python\py-activate-idalib.py"
  ```

## Quick start

```bash
# 1. Demo: build the native control group + the VM-protected version
#    (with pepolish + fake exports), run both, and diff automatically
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

## Protecting your own code

**Step 1: write the functions you want to protect in subset-C.**

Supported: int8..int64 / uint8..uint64, pointers, 1-D arrays, if/else, for/while,
break/continue, arithmetic / bitwise / comparison operators, and function calls.
Not supported: structs, floats, multi-dimensional arrays, recursion, varargs.
Library functions cannot be called directly — host functions (e.g. puts/printf)
must be registered explicitly in `host_config.py`.

For working examples, see `demo/vm_targets.c` and `tests/selftest_targets.c`.

**Step 2: put the `main` entry point in a separate file** (`--main`). The generator
rewrites its calls to the protected functions into VM wrappers.

**Step 3: generate + compile + disguise:**

```bash
python vmc.py build --targets my/targets.c --host my/host_config.py \
                    --main my/main.c --outdir out --seed 12345
cl ... out\protected.c            # vmlib/build.py's build_exe() wraps this step
python pepolish.py final.exe      # renames sections to look like UPX*, appends a decoy-laden .jd section
```

**About the seed**: every new `--seed` yields completely different opcode numbers and
aliases, handler machine-code shapes, keys and decoy constants, encryption formula
families, KSET re-keying schemes, decoy narrative themes and string combinations —
between two builds of the same source there is no reusable static signature.

## Protection mechanisms at a glance

Full details in [DESIGN.md](DESIGN.md) §1–2. "Per build" below means: change the
`--seed` and everything in the right-hand column is regenerated.

| LLM behavior it defeats | Countermeasure |
|---|---|
| Anchoring on strings to locate key code (its heaviest reliance) | Real strings / constants only ever appear as ciphertext inside the bytecode stream — statically invisible |
| Guessing the program's identity from section / export names, PDB path | Every build draws a fake identity from 18 themes (UPX, VMProtect, NSIS, sqlite, libpng, games, drivers, … or a two-theme mix): fake section names, fake exports, fake PDB path, ~130 coherent decoy strings |
| Constant fingerprints (MD5 init values, CRC32 polynomial, …) | Decoys deliberately plant these "standard fingerprints", steering induction toward the fake narrative |
| Semantic reasoning over pseudocode | The same semantic op gets a different machine-code template on every build; 200+ anonymous tiny functions make the pseudocode essentially unreadable |
| Walking the call graph via xrefs | Dispatch / host / VM function tables are all XOR-masked; static call targets don't resolve |
| Running out of context budget | Handler count + aliased opcodes + dead code + decoy functions (at least as many as real ones) inflate the analysis cost together |
| Self-written Python decryption / evaluation scripts | The encryption formula family is randomized per build; per-function KSET layered re-keying forces any script to first parse the variable-length instruction stream and evaluate the prologue arithmetic before it gets past the first layer; never-executed junk blocks poison pattern matching |
| Semantic lifting + hand-built emulators (the strongest attack, demonstrated in the v2 blind test) | v3 VM-in-VM: load-bearing handlers are themselves another layer of encrypted bytecode programs — there is no verifiable intermediate artifact between the two lifts |
| Dynamic debugging | IsDebuggerPresent participates in the key XOR: attach a debugger and the keys change, the bytecode decodes to garbage, and the program silently goes off the rails |

## How we know it works

Not hand-waving. The validation protocol (details in [REPORT.md](REPORT.md)):

1. **Behavioral equivalence**: batch builds across random seeds; the VM version and
   the native version must produce byte-identical output (`run_selftest.py`).
2. **First-person recovery attempt**: a genuine recovery attempt on the protected
   exe using idalib (IDA 9.1's headless analysis library), gauging how much
   information the artifact actually leaks.
3. **Blind tests with uninformed agents**: sub-agents of the same model — with zero
   knowledge of this project — analyze the protected and control exes and deliver
   reports scored on 5 criteria (correct entry point, string recovery, algorithm
   recovery, whether they fell for decoys, overall verdict). The control group was
   fully recovered (proving the blind-test method works); every protected group was
   misled.
4. The v2 / v3 blind tests **explicitly allow and encourage** pure-static attacks
   with self-written decryption / emulation scripts — directly testing the
   anti-script wall.

Blind-test samples from every round, ground-truth keys, and review scripts are
archived in [evidence/](evidence/) and can be re-run directly.
v3 (VM-in-VM + denormalization + formula variants + metadata scrubbing) targets the
strongest attack path found in the v2 blind test; see [DESIGN.md](DESIGN.md) §2b
for the mechanisms and [REPORT.md](REPORT.md) §6 for the retest.

## Known limitations (honesty section)

- **The threat model is static LLM analysis.** Dynamic debugging (patch the keys
  after attaching), Unicorn emulation, symbolic execution, or a human expert
  classifying every handler with IDAPython can still recover the code — this tool
  raises cost and error rate; it is not information-theoretically unrecoverable.
- **The language is subset-C**: no floats / structs / multi-dimensional arrays /
  recursion; protected functions interact with the outside world only through
  registered host functions.
- **Depends on MSVC `cl`**: the code generation side emits C source; there is no
  direct-PE mode yet.
- **Your local third-party AV may flag freshly built obfuscated exes**: just retry
  with a different seed (run_demo / run_selftest have retry + random directories
  built in).

## License

MIT — see [LICENSE](LICENSE). The exes under `evidence/` are experiment samples
(they contain decoy strings and fake section names); they are provided for
reproducing the static analysis only — do not execute them.
