# NIST KAT Verification Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Parse NIST Round 3 KAT files and verify signatures using both Python and Rust implementations.

**Architecture:** Add NIST format parsing to both implementations. The NIST `sm` (signed message) format bundles signature with message. We parse this format, extract components, and verify using existing verify functions. Test against the official `falcon512-KAT.rsp` file.

**Tech Stack:** Rust (falcon-rs), Python (falcon.py), serde_json for KAT parsing

---

## Task 1: Create KAT Parser Script

**Files:**
- Create: `scripts/parse_nist_kat.py`

**Step 1: Write the KAT parser script**

This script parses `falcon512-KAT.rsp` and outputs JSON for both Python and Rust tests.

```python
#!/usr/bin/env python3
"""Parse NIST Falcon-512 KAT file and output JSON test vectors."""
import json
import sys

def parse_kat_file(filepath: str) -> list[dict]:
    """Parse NIST KAT .rsp file."""
    vectors = []
    current = {}

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if line.startswith('count = '):
                if current:
                    vectors.append(current)
                current = {'count': int(line.split(' = ')[1])}
            elif ' = ' in line:
                key, value = line.split(' = ', 1)
                if key == 'mlen' or key == 'smlen':
                    current[key] = int(value)
                else:
                    current[key] = value

    if current:
        vectors.append(current)

    return vectors

def main():
    if len(sys.argv) < 2:
        print("Usage: python parse_nist_kat.py <kat_file.rsp> [count]", file=sys.stderr)
        sys.exit(1)

    filepath = sys.argv[1]
    max_count = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    vectors = parse_kat_file(filepath)[:max_count]
    print(json.dumps(vectors, indent=2))

if __name__ == '__main__':
    main()
```

**Step 2: Run script to generate test vectors**

Run: `python scripts/parse_nist_kat.py falcon-round3/KAT/falcon512-KAT.rsp 10 > test_vectors/nist_kat.json`

Expected: JSON file with 10 test vectors

**Step 3: Verify JSON output**

Run: `head -50 test_vectors/nist_kat.json`

Expected: Valid JSON with count, seed, mlen, msg, pk, sk, smlen, sm fields

**Step 4: Commit**

```bash
git add scripts/parse_nist_kat.py test_vectors/nist_kat.json
git commit -m "feat: add NIST KAT parser script"
```

---

## Task 2: Add NIST Format Parser to Python

**Files:**
- Create: `falcon.py/nist_compat.py`

**Step 1: Write the NIST compatibility module**

```python
"""NIST format compatibility for Falcon signatures."""

# NIST KAT constants for Falcon-512
NIST_SIG_HEADER = 0x29  # 0x20 + 9 (logn for n=512)
NIST_PK_HEADER = 0x09   # 0x00 + 9
NONCELEN = 40


def parse_nist_sm(sm: bytes) -> tuple[bytes, bytes, bytes]:
    """Parse NIST signed-message format.

    NIST sm format:
        [sig_len: 2B BE] [nonce: 40B] [message: msg_len B] [signature: sig_len B]

    Returns:
        (nonce, message, compressed_s1)

    Raises:
        ValueError: if format is invalid
    """
    if len(sm) < 44:  # minimum: 2 + 40 + 0 + 2
        raise ValueError("sm too short")

    sig_len = (sm[0] << 8) | sm[1]
    nonce = sm[2:42]
    msg_len = len(sm) - 2 - NONCELEN - sig_len

    if msg_len < 0:
        raise ValueError("invalid sig_len")

    message = sm[42:42 + msg_len]
    signature = sm[42 + msg_len:]

    if len(signature) != sig_len:
        raise ValueError(f"signature length mismatch: {len(signature)} != {sig_len}")

    if signature[0] != NIST_SIG_HEADER:
        raise ValueError(f"invalid signature header: 0x{signature[0]:02x}, expected 0x{NIST_SIG_HEADER:02x}")

    compressed_s1 = signature[1:]
    return (nonce, message, compressed_s1)


def parse_nist_pk(pk: bytes) -> bytes:
    """Strip NIST header from public key.

    NIST pk format:
        [header: 1B (0x09)] [h: 896B]

    Returns:
        896-byte public key without header

    Raises:
        ValueError: if format is invalid
    """
    if len(pk) != 897:
        raise ValueError(f"invalid pk length: {len(pk)}, expected 897")

    if pk[0] != NIST_PK_HEADER:
        raise ValueError(f"invalid pk header: 0x{pk[0]:02x}, expected 0x{NIST_PK_HEADER:02x}")

    return pk[1:]


def nist_to_falcon_signature(nonce: bytes, compressed_s1: bytes) -> bytes:
    """Convert NIST signature components to falcon.py signature format.

    falcon.py format:
        [header: 1B (0x39)] [salt: 40B] [compressed_s1]
    """
    FALCON_SIG_HEADER = 0x39  # 0x30 + 9
    return bytes([FALCON_SIG_HEADER]) + nonce + compressed_s1
```

**Step 2: Run Python to verify module loads**

Run: `cd falcon.py && python -c "from nist_compat import parse_nist_sm, parse_nist_pk; print('OK')"`

Expected: `OK`

**Step 3: Commit**

```bash
git add falcon.py/nist_compat.py
git commit -m "feat(python): add NIST format parser"
```

---

## Task 3: Add Python NIST KAT Verification Test

**Files:**
- Create: `falcon.py/test_nist_kat.py`

**Step 1: Write the failing test**

```python
#!/usr/bin/env python3
"""Test Falcon verification against NIST KAT vectors."""
import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from falcon import Falcon
from nist_compat import parse_nist_sm, parse_nist_pk, nist_to_falcon_signature


def test_nist_kat_verify():
    """Verify signatures from NIST KAT file."""
    kat_path = Path(__file__).parent.parent / "test_vectors" / "nist_kat.json"

    with open(kat_path) as f:
        vectors = json.load(f)

    falcon = Falcon(512)
    passed = 0
    failed = 0

    for v in vectors:
        count = v['count']
        pk_hex = v['pk']
        msg_hex = v['msg']
        sm_hex = v['sm']

        # Parse hex strings
        pk = bytes.fromhex(pk_hex)
        msg = bytes.fromhex(msg_hex)
        sm = bytes.fromhex(sm_hex)

        try:
            # Parse NIST format
            nonce, extracted_msg, compressed_s1 = parse_nist_sm(sm)
            vk = parse_nist_pk(pk)

            # Verify extracted message matches
            assert extracted_msg == msg, f"message mismatch in KAT {count}"

            # Convert to falcon.py format and verify
            sig = nist_to_falcon_signature(nonce, compressed_s1)
            result = falcon.verify(vk, msg, sig)

            if result:
                passed += 1
                print(f"KAT {count}: PASS")
            else:
                failed += 1
                print(f"KAT {count}: FAIL (verification returned False)")

        except Exception as e:
            failed += 1
            print(f"KAT {count}: FAIL ({e})")

    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


if __name__ == '__main__':
    success = test_nist_kat_verify()
    sys.exit(0 if success else 1)
```

**Step 2: Run test to see current state**

Run: `cd falcon.py && python test_nist_kat.py`

Expected: Either PASS (if formats match) or specific error messages showing what needs fixing

**Step 3: Commit**

```bash
git add falcon.py/test_nist_kat.py
git commit -m "test(python): add NIST KAT verification test"
```

---

## Task 4: Add NIST Format Parser to Rust

**Files:**
- Create: `src/nist_compat.rs`
- Modify: `src/lib.rs`

**Step 1: Write the NIST compatibility module**

```rust
//! NIST format compatibility for Falcon signatures.

use crate::{N, SALT_LEN};
use crate::encoding::deserialize_public_key;
use crate::falcon::{FalconError, Signature, VerifyingKey};

/// NIST KAT constants for Falcon-512.
const NIST_SIG_HEADER: u8 = 0x29; // 0x20 + 9 (logn for n=512)
const NIST_PK_HEADER: u8 = 0x09;  // 0x00 + 9
const NIST_PK_LEN: usize = 897;   // 1 header + 896 body
const NONCELEN: usize = 40;

/// Parsed components from NIST signed-message format.
pub struct NistSmComponents {
    /// The nonce/salt (40 bytes).
    pub nonce: [u8; SALT_LEN],
    /// The original message.
    pub message: Vec<u8>,
    /// The compressed s1 polynomial (without header).
    pub compressed_s1: Vec<u8>,
}

/// Parse NIST signed-message format.
///
/// NIST sm format:
///     [sig_len: 2B BE] [nonce: 40B] [message: msg_len B] [signature: sig_len B]
///
/// Returns the parsed components.
pub fn parse_nist_sm(sm: &[u8]) -> Result<NistSmComponents, FalconError> {
    if sm.len() < 44 {
        return Err(FalconError::InvalidSignature);
    }

    let sig_len = ((sm[0] as usize) << 8) | (sm[1] as usize);

    if sm.len() < 2 + NONCELEN + sig_len {
        return Err(FalconError::InvalidSignature);
    }

    let msg_len = sm.len() - 2 - NONCELEN - sig_len;

    let mut nonce = [0u8; SALT_LEN];
    nonce.copy_from_slice(&sm[2..42]);

    let message = sm[42..42 + msg_len].to_vec();
    let signature = &sm[42 + msg_len..];

    if signature.len() != sig_len {
        return Err(FalconError::InvalidSignature);
    }

    if signature[0] != NIST_SIG_HEADER {
        return Err(FalconError::InvalidSignature);
    }

    let compressed_s1 = signature[1..].to_vec();

    Ok(NistSmComponents {
        nonce,
        message,
        compressed_s1,
    })
}

/// Parse NIST public key format.
///
/// NIST pk format:
///     [header: 1B (0x09)] [h: 896B]
///
/// Returns a VerifyingKey.
pub fn parse_nist_pk(pk: &[u8]) -> Result<VerifyingKey, FalconError> {
    if pk.len() != NIST_PK_LEN {
        return Err(FalconError::InvalidPublicKey);
    }

    if pk[0] != NIST_PK_HEADER {
        return Err(FalconError::InvalidPublicKey);
    }

    let body: [u8; 896] = pk[1..].try_into()
        .map_err(|_| FalconError::InvalidPublicKey)?;

    VerifyingKey::from_bytes(&body)
}

/// Convert NIST signature components to falcon-rs Signature.
pub fn nist_to_falcon_signature(
    nonce: &[u8; SALT_LEN],
    compressed_s1: Vec<u8>,
) -> Signature {
    const FALCON_SIG_HEADER: u8 = 0x39; // 0x30 + 9

    Signature {
        header: FALCON_SIG_HEADER,
        salt: *nonce,
        s1_enc: compressed_s1,
    }
}
```

**Step 2: Update lib.rs to export the module**

Add to `src/lib.rs`:

```rust
pub mod nist_compat;
```

**Step 3: Fix Signature visibility**

The `Signature` struct fields need to be accessible. Modify `src/falcon.rs` to make fields public or add a constructor:

```rust
impl Signature {
    /// Create a signature from components.
    pub fn from_components(header: u8, salt: [u8; SALT_LEN], s1_enc: Vec<u8>) -> Self {
        Signature { header, salt, s1_enc }
    }
}
```

**Step 4: Verify module compiles**

Run: `cargo build --features shake`

Expected: Successful compilation

**Step 5: Commit**

```bash
git add src/nist_compat.rs src/lib.rs src/falcon.rs
git commit -m "feat(rust): add NIST format parser"
```

---

## Task 5: Add Rust NIST KAT Verification Test

**Files:**
- Create: `tests/nist_kat_test.rs`

**Step 1: Write the test**

```rust
//! Test Falcon verification against NIST KAT vectors.

#[cfg(feature = "shake")]
mod tests {
    use falcon_rs::falcon::{Falcon, VerifyingKey};
    use falcon_rs::hash_to_point::Shake256Hash;
    use falcon_rs::nist_compat::{parse_nist_sm, parse_nist_pk, nist_to_falcon_signature};
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

    fn hex_decode(s: &str) -> Vec<u8> {
        hex::decode(s).expect("invalid hex")
    }

    #[test]
    fn test_nist_kat_verify() {
        let kat_json = include_str!("../test_vectors/nist_kat.json");
        let vectors: Vec<NistKatVector> = serde_json::from_str(kat_json)
            .expect("failed to parse KAT JSON");

        let mut passed = 0;
        let mut failed = 0;

        for v in &vectors {
            let pk = hex_decode(&v.pk);
            let msg = hex_decode(&v.msg);
            let sm = hex_decode(&v.sm);

            // Parse NIST format
            let components = match parse_nist_sm(&sm) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("KAT {}: FAIL (sm parse error: {:?})", v.count, e);
                    failed += 1;
                    continue;
                }
            };

            // Verify extracted message matches
            if components.message != msg {
                eprintln!("KAT {}: FAIL (message mismatch)", v.count);
                failed += 1;
                continue;
            }

            // Parse public key
            let vk = match parse_nist_pk(&pk) {
                Ok(vk) => vk,
                Err(e) => {
                    eprintln!("KAT {}: FAIL (pk parse error: {:?})", v.count, e);
                    failed += 1;
                    continue;
                }
            };

            // Convert to falcon-rs format and verify
            let sig = nist_to_falcon_signature(&components.nonce, components.compressed_s1);

            match Falcon::<Shake256Hash>::verify(&vk, &msg, &sig) {
                Ok(true) => {
                    eprintln!("KAT {}: PASS", v.count);
                    passed += 1;
                }
                Ok(false) => {
                    eprintln!("KAT {}: FAIL (verification returned false)", v.count);
                    failed += 1;
                }
                Err(e) => {
                    eprintln!("KAT {}: FAIL (verification error: {:?})", v.count, e);
                    failed += 1;
                }
            }
        }

        eprintln!("\nResults: {} passed, {} failed", passed, failed);
        assert_eq!(failed, 0, "Some KAT vectors failed verification");
    }
}
```

**Step 2: Run the test**

Run: `cargo test --features shake nist_kat_test --release -- --nocapture`

Expected: All KAT vectors pass verification

**Step 3: Commit**

```bash
git add tests/nist_kat_test.rs
git commit -m "test(rust): add NIST KAT verification test"
```

---

## Task 6: Debug and Fix Format Mismatches (if needed)

**Files:**
- Potentially modify: `src/encoding.rs`, `falcon.py/encoding.py`

If tests fail, the most likely issues are:

1. **Public key encoding bit order**: NIST uses different bit packing
2. **Signature compression format**: Subtle differences in unary encoding

**Step 1: Add debug output to identify mismatch**

For Python, add to `test_nist_kat.py`:
```python
# After parsing, print first few bytes for comparison
print(f"  pk header: 0x{pk[0]:02x}")
print(f"  sig header: 0x{signature[0]:02x}")
print(f"  nonce[:8]: {nonce[:8].hex()}")
print(f"  compressed_s1[:16]: {compressed_s1[:16].hex()}")
```

**Step 2: Compare bit ordering in public key serialization**

Check if NIST uses MSB-first vs LSB-first bit packing by examining the C code:
- Look at `modq_encode` in the C reference
- Compare with `serialize_public_key` in Rust

**Step 3: Fix any encoding differences**

If bit order differs, add NIST-specific deserialize functions:

```rust
/// Deserialize NIST public key (may have different bit order).
pub fn deserialize_nist_public_key(bytes: &[u8]) -> Option<[i32; N]> {
    // NIST uses MSB-first bit packing
    // ... adjusted implementation
}
```

**Step 4: Re-run tests after fixes**

Run: `cargo test --features shake nist_kat_test --release -- --nocapture`

Expected: All tests pass

**Step 5: Commit fixes**

```bash
git add -A
git commit -m "fix: correct encoding to match NIST format"
```

---

## Task 7: Run Full Verification Suite

**Files:**
- Modify: `scripts/parse_nist_kat.py` (increase count)

**Step 1: Generate full KAT test vectors**

Run: `python scripts/parse_nist_kat.py falcon-round3/KAT/falcon512-KAT.rsp 100 > test_vectors/nist_kat.json`

**Step 2: Run Python verification on all 100 vectors**

Run: `cd falcon.py && python test_nist_kat.py`

Expected: `Results: 100 passed, 0 failed`

**Step 3: Run Rust verification on all 100 vectors**

Run: `cargo test --features shake nist_kat_test --release -- --nocapture`

Expected: `Results: 100 passed, 0 failed`

**Step 4: Final commit**

```bash
git add test_vectors/nist_kat.json
git commit -m "test: verify all 100 NIST KAT vectors pass"
```

---

## Summary

| Task | Description | Test Command |
|------|-------------|--------------|
| 1 | KAT parser script | `python scripts/parse_nist_kat.py` |
| 2 | Python NIST parser | `python -c "from nist_compat import ..."` |
| 3 | Python KAT test | `python test_nist_kat.py` |
| 4 | Rust NIST parser | `cargo build --features shake` |
| 5 | Rust KAT test | `cargo test --features shake nist_kat_test` |
| 6 | Debug/fix (if needed) | Same as above |
| 7 | Full 100-vector suite | Both Python and Rust tests |

**Key verification points:**
- After Task 3: Python verifies NIST signatures
- After Task 5: Rust verifies NIST signatures
- After Task 7: Both implementations verify all 100 KAT vectors
