"""Per-build keystream schemes. MUST stay bit-identical to the C emitted by
gen_c.py. Every build draws its own parameter set (kmix shape, lane algebra,
byte-select, operand-mix, KSET rekey scheme), so a decryption script written
against one sample does not transfer to the next.

Anti-script design notes:
  * ks8 stays a pure function of (position, keys) — loops revisit positions,
    so the keystream may NOT be chained through execution history.
  * Rekeying therefore happens ONLY via KSET ops in the straight-line function
    prologue: each layer runs exactly once per invocation, in order, so the
    key active at bytecode position p is a static property of p. The Python
    encryptor mirrors the same schedule (codegen.build_function).
"""

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF

PC_SET = (2654435761, 0x9E3779B9, 2246822519, 3266489917, 668265263)
KM_MULS = ((0x5bd1e995, 0x1b873593), (0x85ebca6b, 0xc2b2ae35),
           (0x27220a95, 0x2545f491), (0x9e3779b1, 0x85ebca77))
DXP_SET = (2654435761, 0x45d9f3b, 2246822519, 0x9e3779b9)


def rotl(v, r):
    r &= 31
    v &= M32
    return ((v << r) | (v >> (32 - r))) & M32 if r else v


class Scheme:
    """One build's keystream / operand-mix / rekey parameter set."""

    def __init__(self, rng):
        # kmix shape (finalizer): shifts + multiplier pair
        self.kms1 = rng.choice((13, 12, 14, 11))
        self.kmm1, self.kmm2 = rng.choice(KM_MULS)
        self.kms2 = rng.choice((15, 16, 14))
        self.kms3 = rng.choice((13, 17, 15))
        # ks8 lanes: how p is fed into each key lane, and how lanes combine
        self.pc1 = rng.choice(PC_SET)
        self.rot = rng.choice((3, 5, 7, 11, 13))
        self.l1 = rng.choice(('^', '+'))
        self.l2 = rng.choice(('+', '^'))
        self.l3 = rng.choice(('^', '+'))
        self.cmb = rng.randrange(3)          # 0: x^y^z 1: (x+y)^z 2: x^(y+z)
        self.sh = rng.choice((0, 0, 8, 16))  # output byte select
        # dmx8 (operand de-mix): position-only, key-independent
        self.ds = rng.getrandbits(32)
        self.dp = rng.choice(DXP_SET)
        self.da = rng.randrange(1, 256)
        self.dsh = rng.choice((7, 9, 11, 13))
        # KSET rekey scheme id (see kset_apply / gen_c KSET handler)
        self.kset = rng.randrange(3)

    def kmix(self, x):
        x &= M32
        x ^= x >> self.kms1
        x = (x * self.kmm1) & M32
        x ^= x >> self.kms2
        x = (x * self.kmm2) & M32
        return (x ^ (x >> self.kms3)) & M32

    def ks8(self, p, k1, k2, k3):
        """Keystream byte for bytecode position p (u32 wraps)."""
        p &= M32
        a = (p * self.pc1) & M32
        b = rotl(p, self.rot)
        x = self.kmix((k1 ^ a) if self.l1 == '^' else (k1 + a) & M32)
        y = self.kmix((k2 + p) & M32 if self.l2 == '+' else k2 ^ p)
        z = self.kmix((k3 ^ b) if self.l3 == '^' else (k3 + b) & M32)
        if self.cmb == 0:
            v = x ^ y ^ z
        elif self.cmb == 1:
            v = ((x + y) & M32) ^ z
        else:
            v = x ^ ((y + z) & M32)
        return (v >> self.sh) & 0xFF

    def dmx8(self, p):
        """Operand de-mix byte for the byte fetched at position p."""
        p &= M32
        v = self.kmix(self.ds ^ (((p * self.dp) & M32) + self.da))
        return (v >> self.dsh) & 0xFF

    def dslot8(self, slot, i, k1, k2):
        """Keystream byte for data-slot cipher (slot id, byte index i)."""
        x = self.kmix(k1 ^ ((((slot & 0xFF) * 2654435761) & M32)
                            + ((i * 7) & M32)))
        y = self.kmix((k2 + ((i * 13) & M32) + slot) & M32)
        return (x ^ y) & 0xFF

    def kset_apply(self, k1, k2, k3, d):
        """Rekey (k1,k2,k3) with a u64 delta popped by the KSET op.
        Mirrors the emitted C handler exactly (all lanes u32-wrapping)."""
        lo = d & M32
        hi = (d >> 32) & M32
        if self.kset == 0:
            return (rotl(k1 ^ lo, 1),
                    (k2 + hi + ((lo * 0x9E3779B9) & M32)) & M32,
                    k3 ^ rotl((lo + hi) & M32, 5))
        if self.kset == 1:
            return ((k1 + lo) & M32,
                    rotl(k2 ^ hi, 3),
                    (((k3 ^ ((hi * 0x85EBCA6B) & M32)) & M32) + lo) & M32)
        return (k1 ^ ((lo * 0x27220A95) & M32),
                (k2 - hi) & M32,
                rotl((k3 + lo) & M32, 7) ^ hi)
