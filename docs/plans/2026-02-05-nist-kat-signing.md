# NIST KAT Signing Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement NIST AES-256-CTR-DRBG and test that we can reproduce the exact pk/sk/sm values from the .rsp file using the seed/msg from the .req file.

**Architecture:** The NIST KAT generator uses AES-256-CTR-DRBG (NIST SP 800-90A) seeded with each test vector's `seed` value. We implement this DRBG in both Python and Rust, then use it for key generation and signing. The generated outputs must match the .rsp file exactly.

**Tech Stack:** Rust (falcon-rs), Python (falcon.py), AES-256 (pycryptodome for Python, aes crate for Rust)

---

## Background: How NIST KAT Works

1. Each test vector has a 48-byte `seed` and a `msg`
2. `randombytes_init(seed, NULL, 256)` initializes the DRBG with this seed
3. `crypto_sign_keypair(pk, sk)` calls `randombytes()` internally to generate keys
4. `crypto_sign(sm, &smlen, m, mlen, sk)` calls `randombytes()` for the nonce and signing randomness
5. The DRBG state persists across these calls

The DRBG is AES-256-CTR mode:
- State: 32-byte Key, 16-byte V (counter)
- `randombytes()`: increment V, encrypt with AES-256-ECB, output block, repeat
- After each `randombytes()` call: update Key and V using `AES256_CTR_DRBG_Update`

---

## Task 1: Implement AES-256-CTR-DRBG in Python

**Files:**
- Create: `falcon.py/nist_drbg.py`

**Step 1: Write the DRBG implementation**

```python
"""NIST AES-256-CTR-DRBG implementation for KAT reproduction."""
from Crypto.Cipher import AES


class NistDrbg:
    """AES-256-CTR-DRBG as specified in NIST SP 800-90A."""

    def __init__(self):
        self.key = bytes(32)
        self.v = bytes(16)
        self.reseed_counter = 0

    def _aes256_ecb(self, data: bytes) -> bytes:
        """Single AES-256-ECB block encryption."""
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(data)

    def _increment_v(self):
        """Increment V as a 128-bit big-endian counter."""
        v_int = int.from_bytes(self.v, 'big') + 1
        self.v = (v_int & ((1 << 128) - 1)).to_bytes(16, 'big')

    def _update(self, provided_data: bytes | None):
        """Update Key and V using provided_data (48 bytes or None)."""
        temp = b''
        for _ in range(3):
            self._increment_v()
            temp += self._aes256_ecb(self.v)

        if provided_data is not None:
            temp = bytes(a ^ b for a, b in zip(temp, provided_data))

        self.key = temp[:32]
        self.v = temp[32:48]

    def init(self, entropy: bytes, personalization: bytes | None = None):
        """Initialize DRBG with 48-byte entropy input."""
        if len(entropy) != 48:
            raise ValueError("entropy must be 48 bytes")

        seed_material = bytearray(entropy)
        if personalization:
            for i in range(48):
                seed_material[i] ^= personalization[i]

        self.key = bytes(32)
        self.v = bytes(16)
        self._update(bytes(seed_material))
        self.reseed_counter = 1

    def generate(self, num_bytes: int) -> bytes:
        """Generate random bytes."""
        output = b''
        while len(output) < num_bytes:
            self._increment_v()
            block = self._aes256_ecb(self.v)
            output += block

        self._update(None)
        self.reseed_counter += 1
        return output[:num_bytes]


# Global instance for compatibility with NIST API
_drbg = NistDrbg()


def randombytes_init(entropy: bytes, personalization: bytes = None, security_strength: int = 256):
    """Initialize global DRBG (matches NIST C API)."""
    _drbg.init(entropy, personalization)


def randombytes(num_bytes: int) -> bytes:
    """Generate random bytes from global DRBG (matches NIST C API)."""
    return _drbg.generate(num_bytes)
```

**Step 2: Write unit test for DRBG**

Create simple test to verify DRBG produces deterministic output:

```python
def test_drbg_deterministic():
    from nist_drbg import NistDrbg

    seed = bytes(range(48))

    drbg1 = NistDrbg()
    drbg1.init(seed)
    out1 = drbg1.generate(32)

    drbg2 = NistDrbg()
    drbg2.init(seed)
    out2 = drbg2.generate(32)

    assert out1 == out2
    print("DRBG deterministic test passed")
```

**Step 3: Verify module loads**

Run: `cd falcon.py && python -c "from nist_drbg import randombytes_init, randombytes; print('OK')"`

Expected: `OK`

**Step 4: Commit**

```bash
cd falcon.py && git add nist_drbg.py && git commit -m "feat: add NIST AES-256-CTR-DRBG"
```

---

## Task 2: Test DRBG Against Known Values

**Files:**
- Modify: `falcon.py/nist_drbg.py` (add test)

**Step 1: Compare against C reference output**

We need to verify our DRBG matches the C implementation. The first seed in the KAT is:
`061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1`

After initializing with this seed, the C code generates the keypair. We can compare the first few random bytes.

Add to `nist_drbg.py`:

```python
def test_against_kat():
    """Test DRBG output matches expected values from NIST KAT."""
    seed = bytes.fromhex(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7"
        "056A8C266F9EF97ED08541DBD2E1FFA1"
    )

    drbg = NistDrbg()
    drbg.init(seed)

    # Generate first 48 bytes (what keygen would use for initial randomness)
    first_bytes = drbg.generate(48)
    print(f"First 48 bytes: {first_bytes.hex()}")

    # The exact expected values would need to be extracted from C reference
    # For now, just verify it's deterministic
    drbg2 = NistDrbg()
    drbg2.init(seed)
    assert drbg2.generate(48) == first_bytes
    print("DRBG KAT test passed (deterministic)")


if __name__ == '__main__':
    test_against_kat()
```

**Step 2: Run test**

Run: `cd falcon.py && python nist_drbg.py`

Expected: `DRBG KAT test passed (deterministic)`

**Step 3: Commit**

```bash
cd falcon.py && git add nist_drbg.py && git commit -m "test: add DRBG self-test"
```

---

## Task 3: Implement NIST DRBG in Rust

**Files:**
- Create: `src/nist_drbg.rs`
- Modify: `src/lib.rs`
- Modify: `Cargo.toml` (add aes dependency)

**Step 1: Add aes dependency**

Add to `Cargo.toml` under `[dependencies]`:
```toml
aes = "0.8"
```

**Step 2: Write the DRBG implementation**

Create `src/nist_drbg.rs`:

```rust
//! NIST AES-256-CTR-DRBG implementation for KAT reproduction.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;

/// AES-256-CTR-DRBG state.
pub struct NistDrbg {
    key: [u8; 32],
    v: [u8; 16],
    reseed_counter: u64,
}

impl NistDrbg {
    /// Create uninitialized DRBG.
    pub fn new() -> Self {
        NistDrbg {
            key: [0u8; 32],
            v: [0u8; 16],
            reseed_counter: 0,
        }
    }

    /// AES-256-ECB single block encryption.
    fn aes256_ecb(&self, input: &[u8; 16]) -> [u8; 16] {
        let cipher = Aes256::new((&self.key).into());
        let mut block = *input;
        cipher.encrypt_block((&mut block).into());
        block
    }

    /// Increment V as a 128-bit big-endian counter.
    fn increment_v(&mut self) {
        for i in (0..16).rev() {
            self.v[i] = self.v[i].wrapping_add(1);
            if self.v[i] != 0 {
                break;
            }
        }
    }

    /// Update Key and V using provided_data (48 bytes or None).
    fn update(&mut self, provided_data: Option<&[u8; 48]>) {
        let mut temp = [0u8; 48];

        for i in 0..3 {
            self.increment_v();
            let block = self.aes256_ecb(&self.v);
            temp[i * 16..(i + 1) * 16].copy_from_slice(&block);
        }

        if let Some(data) = provided_data {
            for i in 0..48 {
                temp[i] ^= data[i];
            }
        }

        self.key.copy_from_slice(&temp[..32]);
        self.v.copy_from_slice(&temp[32..48]);
    }

    /// Initialize DRBG with 48-byte entropy input.
    pub fn init(&mut self, entropy: &[u8; 48], personalization: Option<&[u8; 48]>) {
        let mut seed_material = *entropy;
        if let Some(pers) = personalization {
            for i in 0..48 {
                seed_material[i] ^= pers[i];
            }
        }

        self.key = [0u8; 32];
        self.v = [0u8; 16];
        self.update(Some(&seed_material));
        self.reseed_counter = 1;
    }

    /// Generate random bytes.
    pub fn generate(&mut self, output: &mut [u8]) {
        let mut pos = 0;
        while pos < output.len() {
            self.increment_v();
            let block = self.aes256_ecb(&self.v);
            let copy_len = (output.len() - pos).min(16);
            output[pos..pos + copy_len].copy_from_slice(&block[..copy_len]);
            pos += copy_len;
        }

        self.update(None);
        self.reseed_counter += 1;
    }

    /// Generate and return a Vec of random bytes.
    pub fn generate_vec(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut output = vec![0u8; num_bytes];
        self.generate(&mut output);
        output
    }
}

impl Default for NistDrbg {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drbg_deterministic() {
        let seed: [u8; 48] = core::array::from_fn(|i| i as u8);

        let mut drbg1 = NistDrbg::new();
        drbg1.init(&seed, None);
        let out1 = drbg1.generate_vec(32);

        let mut drbg2 = NistDrbg::new();
        drbg2.init(&seed, None);
        let out2 = drbg2.generate_vec(32);

        assert_eq!(out1, out2);
    }
}
```

**Step 3: Update lib.rs**

Add to `src/lib.rs`:
```rust
pub mod nist_drbg;
```

**Step 4: Verify it compiles**

Run: `cargo build --features shake`

Expected: Successful compilation

**Step 5: Run DRBG tests**

Run: `cargo test nist_drbg`

Expected: Test passes

**Step 6: Commit**

```bash
git add Cargo.toml src/nist_drbg.rs src/lib.rs
git commit -m "feat(rust): add NIST AES-256-CTR-DRBG"
```

---

## Task 4: Verify DRBG Cross-Language Consistency

**Files:**
- Create: `scripts/compare_drbg.py`

**Step 1: Create comparison script**

This script generates DRBG output from both Python and Rust and compares them.

```python
#!/usr/bin/env python3
"""Compare DRBG output between Python and Rust implementations."""
import subprocess
import sys
sys.path.insert(0, 'falcon.py')

from nist_drbg import NistDrbg

def main():
    # Use first KAT seed
    seed = bytes.fromhex(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7"
        "056A8C266F9EF97ED08541DBD2E1FFA1"
    )

    # Python output
    drbg = NistDrbg()
    drbg.init(seed)
    py_out = drbg.generate(64)
    print(f"Python: {py_out.hex()}")

    # Rust output (via test binary - we'll create this)
    # For now, just print Python output for manual comparison
    print("\nTo compare with Rust, run:")
    print(f"  cargo test --features shake test_drbg_kat_seed -- --nocapture")


if __name__ == '__main__':
    main()
```

**Step 2: Add Rust test with same seed**

Add to `src/nist_drbg.rs` tests:

```rust
#[test]
fn test_drbg_kat_seed() {
    // First KAT seed
    let seed = hex::decode(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7\
         056A8C266F9EF97ED08541DBD2E1FFA1"
    ).unwrap();

    let mut seed_arr = [0u8; 48];
    seed_arr.copy_from_slice(&seed);

    let mut drbg = NistDrbg::new();
    drbg.init(&seed_arr, None);
    let output = drbg.generate_vec(64);

    eprintln!("Rust: {}", hex::encode(&output));
}
```

**Step 3: Compare outputs**

Run Python: `python scripts/compare_drbg.py`
Run Rust: `cargo test --features shake test_drbg_kat_seed -- --nocapture 2>&1 | grep Rust`

Both should produce identical output.

**Step 4: Commit**

```bash
git add scripts/compare_drbg.py src/nist_drbg.rs
git commit -m "test: add DRBG cross-language comparison"
```

---

## Task 5: Create Python KAT Signing Test

**Files:**
- Create: `falcon.py/test_nist_kat_sign.py`

**Step 1: Write the signing reproduction test**

This test:
1. Reads each .req vector (seed, msg)
2. Initializes DRBG with seed
3. Generates keypair using DRBG
4. Signs message using DRBG
5. Compares pk, sk, sm with .rsp values

```python
#!/usr/bin/env python3
"""Test that we can reproduce NIST KAT signatures using the DRBG."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from nist_drbg import NistDrbg
from falcon import Falcon
from nist_compat import NIST_SIG_HEADER, NIST_PK_HEADER


def serialize_nist_pk(h: list[int]) -> bytes:
    """Serialize public key in NIST big-endian format."""
    # Header byte
    output = bytes([NIST_PK_HEADER])

    # Big-endian 14-bit packing
    acc = 0
    acc_len = 0
    for coef in h:
        acc = (acc << 14) | coef
        acc_len += 14
        while acc_len >= 8:
            acc_len -= 8
            output += bytes([(acc >> acc_len) & 0xFF])

    return output


def create_nist_sm(sig: bytes, msg: bytes) -> bytes:
    """Create NIST signed-message format."""
    # sig is falcon.py format: [0x39][salt][compressed_s1]
    salt = sig[1:41]
    compressed_s1 = sig[41:]

    # NIST signature: [0x29][compressed_s1]
    nist_sig = bytes([NIST_SIG_HEADER]) + compressed_s1
    sig_len = len(nist_sig)

    # sm = [sig_len:2B BE][nonce:40B][msg][signature]
    sm = sig_len.to_bytes(2, 'big') + salt + msg + nist_sig
    return sm


def test_nist_kat_sign():
    """Reproduce KAT signatures using NIST DRBG."""
    kat_path = Path(__file__).parent.parent / "test_vectors" / "nist_kat.json"

    with open(kat_path) as f:
        vectors = json.load(f)

    passed = 0
    failed = 0

    for v in vectors[:5]:  # Start with first 5
        count = v['count']
        seed = bytes.fromhex(v['seed'])
        msg = bytes.fromhex(v['msg'])
        expected_pk = bytes.fromhex(v['pk'])
        expected_sm = bytes.fromhex(v['sm'])

        try:
            # Initialize DRBG with seed
            drbg = NistDrbg()
            drbg.init(seed)

            # Create Falcon instance with DRBG
            falcon = Falcon(512)

            # Generate keypair using DRBG
            def randombytes(n):
                return drbg.generate(n)

            sk, vk = falcon.keygen(randombytes=randombytes)

            # Serialize pk in NIST format
            h = list(vk)  # vk is the public key polynomial
            pk = serialize_nist_pk(h)

            if pk != expected_pk:
                print(f"KAT {count}: FAIL (pk mismatch)")
                print(f"  Expected: {expected_pk[:32].hex()}...")
                print(f"  Got:      {pk[:32].hex()}...")
                failed += 1
                continue

            # Sign message using DRBG
            sig = falcon.sign(sk, msg, randombytes=randombytes)

            # Create NIST sm format
            sm = create_nist_sm(sig, msg)

            if sm != expected_sm:
                print(f"KAT {count}: FAIL (sm mismatch)")
                print(f"  Expected len: {len(expected_sm)}, Got: {len(sm)}")
                failed += 1
                continue

            print(f"KAT {count}: PASS")
            passed += 1

        except Exception as e:
            print(f"KAT {count}: FAIL ({e})")
            import traceback
            traceback.print_exc()
            failed += 1

    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


if __name__ == '__main__':
    success = test_nist_kat_sign()
    sys.exit(0 if success else 1)
```

**Step 2: Run the test**

Run: `cd falcon.py && python test_nist_kat_sign.py`

Expected: This will likely fail initially - we need to debug the exact format differences.

**Step 3: Commit**

```bash
cd falcon.py && git add test_nist_kat_sign.py
git commit -m "test(python): add NIST KAT signing reproduction test (WIP)"
```

---

## Task 6: Debug and Fix Format Differences

**Files:**
- Potentially modify: `falcon.py/falcon.py`, `falcon.py/nist_compat.py`

This task involves debugging why the generated pk/sm don't match the expected values. Common issues:

1. **Public key serialization bit order** - NIST uses big-endian 14-bit packing
2. **Secret key format** - NIST packs f, g, F differently than falcon.py
3. **Signature format** - The compression algorithm must match exactly
4. **SHAKE256 randomness** - Keygen uses SHAKE256 seeded from DRBG output

**Step 1: Add debug output to identify first mismatch**

Modify `test_nist_kat_sign.py` to print byte-by-byte comparison when pk doesn't match.

**Step 2: Compare keygen randomness usage**

The C reference uses randomness differently:
1. Generate 48-byte seed from DRBG
2. Use SHAKE256 seeded with that to generate f, g polynomials

Check if falcon.py does the same.

**Step 3: Fix any differences found**

Create NIST-compatible functions if needed.

**Step 4: Commit fixes**

```bash
cd falcon.py && git add -A && git commit -m "fix: align keygen/sign with NIST reference"
```

---

## Task 7: Create Rust KAT Signing Test

**Files:**
- Create: `tests/nist_kat_sign_test.rs`

Similar to Task 5 but for Rust. This is complex because we need to:
1. Wire the NIST DRBG into keygen
2. Serialize pk/sk in NIST format
3. Create sm in NIST format

**Step 1: Create test file**

```rust
//! Test NIST KAT signing reproduction.

#[cfg(feature = "shake")]
mod tests {
    use falcon_rs::nist_drbg::NistDrbg;
    use falcon_rs::falcon::Falcon;
    use falcon_rs::hash_to_point::Shake256Hash;
    use falcon_rs::nist_compat::{serialize_nist_pk, create_nist_sm};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct NistKatVector {
        count: u32,
        seed: String,
        mlen: usize,
        msg: String,
        pk: String,
        sk: String,
        smlen: usize,
        sm: String,
    }

    #[test]
    fn test_nist_kat_sign() {
        let kat_json = include_str!("../test_vectors/nist_kat.json");
        let vectors: Vec<NistKatVector> = serde_json::from_str(kat_json).unwrap();

        for v in vectors.iter().take(5) {
            let seed = hex::decode(&v.seed).unwrap();
            let msg = hex::decode(&v.msg).unwrap();
            let expected_pk = hex::decode(&v.pk).unwrap();
            let expected_sm = hex::decode(&v.sm).unwrap();

            // Initialize DRBG
            let mut seed_arr = [0u8; 48];
            seed_arr.copy_from_slice(&seed);
            let mut drbg = NistDrbg::new();
            drbg.init(&seed_arr, None);

            // Generate keypair using DRBG
            let mut randombytes = |n: usize| drbg.generate_vec(n);
            let (sk, vk) = Falcon::<Shake256Hash>::keygen_with_rng(&mut randombytes);

            // Serialize pk in NIST format
            let pk = serialize_nist_pk(&vk);

            assert_eq!(pk, expected_pk, "KAT {}: pk mismatch", v.count);

            // Sign and create sm
            // ... (similar to Python)

            eprintln!("KAT {}: PASS", v.count);
        }
    }
}
```

**Step 2: Add serialize_nist_pk to nist_compat.rs**

**Step 3: Run test and debug**

**Step 4: Commit**

```bash
git add tests/nist_kat_sign_test.rs src/nist_compat.rs
git commit -m "test(rust): add NIST KAT signing reproduction test"
```

---

## Task 8: Run Full Signing KAT Suite

**Files:**
- Modify tests to run all 100 vectors

**Step 1: Update Python test to run all 100 vectors**

**Step 2: Update Rust test to run all 100 vectors**

**Step 3: Run both and verify all pass**

**Step 4: Final commit**

```bash
git add -A
git commit -m "test: verify all 100 NIST KAT signing vectors reproduce correctly"
```

---

## Summary

| Task | Description | Complexity |
|------|-------------|------------|
| 1 | Python NIST DRBG | Medium |
| 2 | Test DRBG against known values | Easy |
| 3 | Rust NIST DRBG | Medium |
| 4 | Cross-language DRBG comparison | Easy |
| 5 | Python KAT signing test | Hard |
| 6 | Debug format differences | Hard (unknown scope) |
| 7 | Rust KAT signing test | Hard |
| 8 | Full 100-vector suite | Easy |

**Key challenges:**
- NIST keygen uses SHAKE256 seeded from DRBG, not DRBG directly
- Secret key serialization format differs between implementations
- Exact byte-level matching requires careful attention to bit packing

**Expected outcome:**
Both Python and Rust can reproduce all 100 NIST KAT signatures bit-for-bit.
