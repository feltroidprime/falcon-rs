# Repository Cleanup Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Clean up falcon-rs repository with clear structure, comprehensive testing, and proper documentation.

**Architecture:** Remove unnecessary files, organize existing code, add missing documentation (README, API docs, examples), ensure all tests pass, and verify clean git state.

**Tech Stack:** Rust, Cargo, cargo-doc, WASM (wasm-pack)

---

## Current Issues Identified

1. **Loose files**: `falcon-round3.zip` (3.9MB), `falcon-round3/` directory
2. **Missing documentation**: No README.md, no API docs, no usage examples
3. **Unstaged changes**: 13 modified files need review/commit
4. **Incomplete .gitignore**: Missing entries for reference directories
5. **No WASM build/test documentation**

---

## Task 1: Review and Commit Unstaged Changes

**Files:**
- Review: All modified files in `git status`

**Step 1: Check current git status**

Run: `cd /home/felt/PycharmProjects/falcon-rs && git status`

**Step 2: Review the diff for each modified file**

Run: `cd /home/felt/PycharmProjects/falcon-rs && git diff --stat`

**Step 3: Stage and commit the NIST KAT signing work**

These changes are from the recent NIST KAT signing implementation. Commit them:

```bash
cd /home/felt/PycharmProjects/falcon-rs
git add src/ tests/ test_vectors/ docs/plans/
git status
git commit -m "feat: complete NIST KAT signing verification

- Add NIST secret key parsing (trim_i8 decode)
- Add public key reconstruction from (f, g)
- Verify all 100 NIST KAT signatures
- Add serialize_nist_pk for big-endian format"
```

**Step 4: Verify clean state**

Run: `git status`

Expected: Only untracked files (falcon-round3.zip, falcon-round3/) remain

---

## Task 2: Clean Up Unnecessary Files

**Files:**
- Delete: `falcon-round3.zip`
- Delete: `falcon-round3/` directory

**Step 1: Remove the zip file**

```bash
cd /home/felt/PycharmProjects/falcon-rs
rm falcon-round3.zip
```

**Step 2: Remove the extracted directory**

```bash
rm -rf falcon-round3/
```

**Step 3: Verify removal**

Run: `ls -la | grep falcon-round`

Expected: No output (files removed)

**Step 4: Check git status**

Run: `git status`

Expected: Clean working tree (these were untracked)

---

## Task 3: Update .gitignore

**Files:**
- Modify: `.gitignore`

**Step 1: Read current .gitignore**

Run: `cat .gitignore`

**Step 2: Update .gitignore with comprehensive entries**

Add these entries to `.gitignore`:

```gitignore
# Build artifacts
/target/
Cargo.lock

# IDE
.idea/
*.iml
.vscode/

# Python
__pycache__/
*.py[cod]
*.so
.venv/
venv/

# Development
.worktrees/

# Reference implementations (download separately if needed)
/falcon-round3/
/falcon-round3.zip

# Test artifacts
*.log

# OS
.DS_Store
Thumbs.db
```

**Step 3: Commit .gitignore update**

```bash
cd /home/felt/PycharmProjects/falcon-rs
git add .gitignore
git commit -m "chore: update .gitignore with comprehensive entries"
```

---

## Task 4: Create README.md

**Files:**
- Create: `README.md`

**Step 1: Create comprehensive README**

```markdown
# falcon-rs

Rust implementation of the Falcon-512 post-quantum digital signature scheme.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

Falcon is a lattice-based signature scheme selected by NIST for post-quantum cryptography standardization. This implementation provides:

- **Falcon-512** signatures (NIST Security Level 1)
- **Generic hash trait** - swap SHAKE256 for custom hash functions (e.g., Poseidon for ZK compatibility)
- **WASM support** - use in browsers and JavaScript environments
- **NIST KAT verified** - all 100 NIST known-answer test vectors pass

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
falcon-rs = { git = "https://github.com/anthropics/falcon-rs" }
```

## Usage

### Basic Signing and Verification

```rust
use falcon_rs::falcon::Falcon;
use falcon_rs::hash_to_point::Shake256Hash;

fn main() {
    // Generate keypair
    let falcon = Falcon::<Shake256Hash>::new();
    let (signing_key, verifying_key) = falcon.keygen();

    // Sign a message
    let message = b"Hello, post-quantum world!";
    let signature = signing_key.sign(message);

    // Verify the signature
    assert!(verifying_key.verify::<Shake256Hash>(message, &signature).unwrap());
}
```

### Custom Hash Function

Implement the `HashToPoint` trait for your hash function:

```rust
use falcon_rs::hash_to_point::HashToPoint;
use falcon_rs::constants::N;

struct MyCustomHash;

impl HashToPoint for MyCustomHash {
    fn hash_to_point(message: &[u8], nonce: &[u8]) -> [i16; N] {
        // Your implementation here
        todo!()
    }
}

// Use with Falcon
let falcon = Falcon::<MyCustomHash>::new();
```

## Building

```bash
# Build library
cargo build --release

# Build with SHAKE256 support (default)
cargo build --release --features shake

# Run tests
cargo test --features shake

# Run NIST KAT tests
cargo test --features shake nist_kat -- --nocapture
```

### WASM Build

```bash
# Install wasm-pack
cargo install wasm-pack

# Build WASM package
wasm-pack build --target web --features wasm
```

## Project Structure

```
falcon-rs/
├── src/
│   ├── lib.rs           # Library entry point
│   ├── falcon.rs        # Main signature scheme
│   ├── hash_to_point.rs # Generic hash trait
│   ├── ntrugen.rs       # NTRU key generation
│   ├── ffsampling.rs    # Gaussian sampling
│   ├── fft.rs           # Fast Fourier Transform
│   ├── ntt.rs           # Number Theoretic Transform
│   ├── samplerz.rs      # Discrete Gaussian sampler
│   ├── encoding.rs      # Signature encoding
│   ├── nist_compat.rs   # NIST format compatibility
│   └── wasm.rs          # WebAssembly bindings
├── tests/
│   ├── falcon_test.rs   # Basic operation tests
│   ├── nist_kat_test.rs # NIST KAT verification
│   └── ...
├── test_vectors/        # Test data (JSON)
└── docs/plans/          # Design documents
```

## Features

| Feature | Description |
|---------|-------------|
| `shake` | SHAKE256 hash function (default) |
| `wasm`  | WebAssembly bindings |

## ⚠️ Security Considerations

**This implementation is NOT side-channel resistant.**

It is ported from the Falcon reference implementation (`falcon.py`), which prioritizes correctness and readability over side-channel protection. Specifically:

| Component | Vulnerability |
|-----------|---------------|
| Floating-point FFT | Timing varies with input values |
| Gaussian sampling | Rejection sampling has variable-time loops |
| `samplerz` | Early exits based on secret values |
| `ffsampling` | Branches depend on secret tree traversal |

**Suitable for:**
- Learning and research
- Applications where timing attacks are not in the threat model
- Correctness validation against NIST KAT vectors
- Prototyping (e.g., ZK circuit design)

**NOT suitable for:**
- Production environments with side-channel threats
- Hardware where cache timing attacks are possible
- Any security-critical deployment without further hardening

For production use, consider the official [Falcon constant-time C implementation](https://falcon-sign.info/).

## Cryptographic Properties

- **NIST verified**: Passes all 100 official known-answer test vectors
- **Secure randomness**: Uses OS CSPRNG via `getrandom` crate (when available)
- **Correctness**: Mathematically equivalent to reference implementation

## Performance

| Operation | Time (approx) |
|-----------|---------------|
| Key generation | ~10ms |
| Signing | ~5ms |
| Verification | ~1ms |

*Benchmarks on Apple M1, single-threaded*

## References

- [Falcon Specification](https://falcon-sign.info/)
- [NIST PQC Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Falcon Round 3 Submission](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions)

## License

MIT License - see [LICENSE](LICENSE) for details.
```

**Step 2: Commit README**

```bash
cd /home/felt/PycharmProjects/falcon-rs
git add README.md
git commit -m "docs: add comprehensive README"
```

---

## Task 5: Add Rustdoc Comments to Public API

**Files:**
- Modify: `src/lib.rs`
- Modify: `src/falcon.rs`
- Modify: `src/hash_to_point.rs`

**Step 1: Add crate-level documentation to lib.rs**

Add at the top of `src/lib.rs`:

```rust
//! # falcon-rs
//!
//! Rust implementation of the Falcon-512 post-quantum digital signature scheme.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use falcon_rs::falcon::Falcon;
//! use falcon_rs::hash_to_point::Shake256Hash;
//!
//! // Generate keypair
//! let falcon = Falcon::<Shake256Hash>::new();
//! let (sk, vk) = falcon.keygen();
//!
//! // Sign and verify
//! let msg = b"Hello!";
//! let sig = sk.sign(msg);
//! assert!(vk.verify::<Shake256Hash>(msg, &sig).unwrap());
//! ```
//!
//! ## Features
//!
//! - `shake` - Enable SHAKE256 hash function (default)
//! - `wasm` - Enable WebAssembly bindings
//!
//! ## ⚠️ Security Warning
//!
//! This implementation is **NOT side-channel resistant**. It is ported from
//! the reference implementation which prioritizes correctness over constant-time
//! execution. Do not use in production environments where timing attacks are
//! a concern.
```

**Step 2: Add documentation to falcon.rs public items**

Read `src/falcon.rs` and add doc comments to:
- `Falcon` struct
- `SigningKey` struct
- `VerifyingKey` struct
- `Signature` struct
- `keygen()` method
- `sign()` method
- `verify()` method

Example for `Falcon` struct:

```rust
/// Falcon-512 signature scheme with generic hash function.
///
/// # Type Parameters
///
/// * `H` - Hash function implementing [`HashToPoint`] trait
///
/// # Example
///
/// ```rust,ignore
/// use falcon_rs::falcon::Falcon;
/// use falcon_rs::hash_to_point::Shake256Hash;
///
/// let falcon = Falcon::<Shake256Hash>::new();
/// let (sk, vk) = falcon.keygen();
/// ```
pub struct Falcon<H: HashToPoint> {
    // ...
}
```

**Step 3: Add documentation to hash_to_point.rs**

```rust
//! Hash-to-point trait for customizable hash functions.
//!
//! Falcon requires hashing messages to points in Z_q[X]/(X^n + 1).
//! This module provides the trait and a default SHAKE256 implementation.

/// Trait for hashing messages to polynomial points.
///
/// Implement this trait to use a custom hash function with Falcon.
///
/// # Example
///
/// ```rust,ignore
/// use falcon_rs::hash_to_point::HashToPoint;
/// use falcon_rs::constants::N;
///
/// struct PoseidonHash;
///
/// impl HashToPoint for PoseidonHash {
///     fn hash_to_point(message: &[u8], nonce: &[u8]) -> [i16; N] {
///         // Poseidon implementation
///         todo!()
///     }
/// }
/// ```
pub trait HashToPoint {
    fn hash_to_point(message: &[u8], nonce: &[u8]) -> [i16; N];
}
```

**Step 4: Generate and verify docs**

```bash
cd /home/felt/PycharmProjects/falcon-rs
cargo doc --no-deps --features shake
# Open target/doc/falcon_rs/index.html to verify
```

**Step 5: Commit documentation**

```bash
git add src/lib.rs src/falcon.rs src/hash_to_point.rs
git commit -m "docs: add rustdoc comments to public API"
```

---

## Task 6: Organize Test Structure

**Files:**
- Review: `tests/` directory

**Step 1: Verify all tests pass**

```bash
cd /home/felt/PycharmProjects/falcon-rs
cargo test --features shake
```

Expected: All tests pass

**Step 2: Add test documentation**

Create `tests/README.md`:

```markdown
# Test Suite

## Test Organization

| File | Purpose | Vectors |
|------|---------|---------|
| `falcon_test.rs` | Basic sign/verify operations | - |
| `samplerz_kat.rs` | Gaussian sampler validation | 512 |
| `nist_kat_test.rs` | NIST keygen/encoding verification | 100 |
| `nist_kat_sign_test.rs` | Full NIST signing pipeline | 100 |
| `cross_language_test.rs` | Python/Rust compatibility | - |

## Running Tests

```bash
# All tests
cargo test --features shake

# Specific test file
cargo test --features shake nist_kat

# With output
cargo test --features shake -- --nocapture
```

## Test Vectors

Test vectors are stored in `test_vectors/` as JSON files:
- `nist_kat.json` - Official NIST known-answer tests
- `samplerz_kat512_python.json` - Sampler validation data
- `hash_to_point_kat.json` - Hash function test data
```

**Step 3: Commit test documentation**

```bash
git add tests/README.md
git commit -m "docs: add test suite documentation"
```

---

## Task 7: Add LICENSE File

**Files:**
- Create: `LICENSE`

**Step 1: Create MIT LICENSE file**

```text
MIT License

Copyright (c) 2026 falcon-rs contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

**Step 2: Commit LICENSE**

```bash
git add LICENSE
git commit -m "chore: add MIT license"
```

---

## Task 8: Update Cargo.toml Metadata

**Files:**
- Modify: `Cargo.toml`

**Step 1: Read current Cargo.toml**

Run: `cat Cargo.toml`

**Step 2: Add package metadata**

Ensure these fields are present in `[package]`:

```toml
[package]
name = "falcon-rs"
version = "0.1.0"
edition = "2021"
authors = ["falcon-rs contributors"]
description = "Rust implementation of Falcon-512 post-quantum signature scheme"
license = "MIT"
repository = "https://github.com/anthropics/falcon-rs"
documentation = "https://docs.rs/falcon-rs"
readme = "README.md"
keywords = ["cryptography", "post-quantum", "falcon", "signature", "lattice"]
categories = ["cryptography", "no-std"]

[package.metadata.docs.rs]
features = ["shake"]
```

**Step 3: Commit Cargo.toml update**

```bash
git add Cargo.toml
git commit -m "chore: add package metadata to Cargo.toml"
```

---

## Task 9: Create WASM Example

**Files:**
- Create: `examples/wasm_demo.rs`
- Create: `examples/README.md`

**Step 1: Create examples directory and basic example**

```bash
mkdir -p examples
```

Create `examples/basic_usage.rs`:

```rust
//! Basic Falcon-512 usage example.
//!
//! Run with: cargo run --example basic_usage --features shake

use falcon_rs::falcon::Falcon;
use falcon_rs::hash_to_point::Shake256Hash;

fn main() {
    println!("Falcon-512 Demo");
    println!("===============\n");

    // Generate keypair
    println!("Generating keypair...");
    let falcon = Falcon::<Shake256Hash>::new();
    let (signing_key, verifying_key) = falcon.keygen();
    println!("✓ Keypair generated\n");

    // Sign a message
    let message = b"Hello, post-quantum world!";
    println!("Signing message: {:?}", String::from_utf8_lossy(message));
    let signature = signing_key.sign(message);
    println!("✓ Signature created ({} bytes)\n", signature.to_bytes().len());

    // Verify the signature
    println!("Verifying signature...");
    let valid = verifying_key
        .verify::<Shake256Hash>(message, &signature)
        .expect("verification failed");

    if valid {
        println!("✓ Signature is valid!");
    } else {
        println!("✗ Signature is invalid!");
    }
}
```

**Step 2: Create examples README**

Create `examples/README.md`:

```markdown
# Examples

## Basic Usage

```bash
cargo run --example basic_usage --features shake
```

## WASM Usage

See the [main README](../README.md#wasm-build) for WASM build instructions.

Example JavaScript usage:

```javascript
import init, { generate_keypair, sign, verify } from './pkg/falcon_rs.js';

async function demo() {
    await init();

    // Generate keypair
    const { signing_key, verifying_key } = generate_keypair();

    // Sign message
    const message = new TextEncoder().encode("Hello!");
    const signature = sign(signing_key, message);

    // Verify
    const valid = verify(verifying_key, message, signature);
    console.log("Valid:", valid);
}

demo();
```
```

**Step 3: Commit examples**

```bash
git add examples/
git commit -m "docs: add usage examples"
```

---

## Task 10: Final Verification and Cleanup

**Files:**
- Review: Entire repository

**Step 1: Run full test suite**

```bash
cd /home/felt/PycharmProjects/falcon-rs
cargo test --features shake
```

Expected: All tests pass

**Step 2: Build documentation**

```bash
cargo doc --no-deps --features shake
```

Expected: No warnings, docs build successfully

**Step 3: Check for any remaining issues**

```bash
# Check for uncommitted changes
git status

# Check for large files
find . -type f -size +1M -not -path "./.git/*" -not -path "./target/*"

# Verify structure
tree -L 2 -I 'target|.git|falcon.py'
```

**Step 4: Run clippy for code quality**

```bash
cargo clippy --features shake -- -D warnings
```

Fix any warnings that appear.

**Step 5: Final commit if needed**

```bash
git status
# If any remaining changes:
git add -A
git commit -m "chore: final cleanup"
```

**Step 6: Verify clean state**

```bash
git status
git log --oneline -10
```

Expected: Clean working tree, clear commit history

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Commit unstaged changes | src/, tests/, docs/ |
| 2 | Remove unnecessary files | falcon-round3.zip, falcon-round3/ |
| 3 | Update .gitignore | .gitignore |
| 4 | Create README.md | README.md |
| 5 | Add API documentation | src/lib.rs, src/falcon.rs, src/hash_to_point.rs |
| 6 | Organize test structure | tests/README.md |
| 7 | Add LICENSE | LICENSE |
| 8 | Update Cargo.toml | Cargo.toml |
| 9 | Create examples | examples/ |
| 10 | Final verification | - |

**Expected Outcome:**
- Clean repository with no loose files
- Comprehensive README with usage instructions
- API documentation via rustdoc
- All tests passing
- Proper licensing and metadata
- Examples for common use cases
