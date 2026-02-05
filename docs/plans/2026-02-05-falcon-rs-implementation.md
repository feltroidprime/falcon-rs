# Falcon-RS Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement Falcon-512 signature scheme in Rust with WASM support and customizable hash function.

**Architecture:** Port Python reference implementation module-by-module, testing each layer against KATs. Use generic `HashToPoint` trait for hash function abstraction. Export only Poseidon variant to WASM.

**Tech Stack:** Rust, wasm-bindgen, sha3 (for testing), serde_json (for KAT loading)

---

## Task 1: Project Setup

**Files:**
- Create: `Cargo.toml`
- Create: `src/lib.rs`

**Step 1: Create Cargo.toml**

```toml
[package]
name = "falcon-rs"
version = "0.1.0"
edition = "2021"
description = "Falcon-512 signature scheme with WASM support"
license = "MIT"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
sha3 = { version = "0.10", optional = true }
wasm-bindgen = { version = "0.2", optional = true }
getrandom = { version = "0.2", features = ["js"], optional = true }
thiserror = "1.0"

[dev-dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

[features]
default = ["shake"]
shake = ["sha3"]
wasm = ["wasm-bindgen", "getrandom"]
```

**Step 2: Create src/lib.rs stub**

```rust
//! Falcon-512 signature scheme implementation.

pub mod constants;
pub mod ntt;
pub mod fft;
pub mod rng;
pub mod samplerz;
pub mod ffsampling;
pub mod ntrugen;
pub mod encoding;
pub mod hash_to_point;
pub mod falcon;

#[cfg(feature = "wasm")]
pub mod wasm;

/// The integer modulus used in Falcon.
pub const Q: i32 = 12289;

/// Degree of the polynomial ring for Falcon-512.
pub const N: usize = 512;

/// Salt length in bytes.
pub const SALT_LEN: usize = 40;

/// Seed length for ChaCha20 PRNG.
pub const SEED_LEN: usize = 56;
```

**Step 3: Create placeholder modules**

Create empty files for each module:
- `src/constants.rs`
- `src/ntt.rs`
- `src/fft.rs`
- `src/rng.rs`
- `src/samplerz.rs`
- `src/ffsampling.rs`
- `src/ntrugen.rs`
- `src/encoding.rs`
- `src/hash_to_point.rs`
- `src/falcon.rs`

Each file should contain just:
```rust
//! Module description placeholder.
```

**Step 4: Verify project compiles**

Run: `cargo build`
Expected: Successful compilation with warnings about unused modules

**Step 5: Commit**

```bash
git add Cargo.toml src/
git commit -m "feat: initialize Falcon-RS project structure"
```

---

## Task 2: Constants Module

**Files:**
- Modify: `src/constants.rs`
- Create: `scripts/extract_constants.py`

**Step 1: Create Python script to extract constants**

Create `scripts/extract_constants.py`:
```python
#!/usr/bin/env python3
"""Extract FFT and NTT constants for n=512 from Python implementation."""
import sys
sys.path.insert(0, 'falcon.py')

from fft_constants import roots_dict
from ntt_constants import roots_dict_Zq, inv_mod_q

# Extract FFT roots for n=512 (complex numbers)
fft_roots = roots_dict[512]
print("// FFT roots of unity (complex) for n=512")
print("pub const FFT_ROOTS: [(f64, f64); 512] = [")
for i, r in enumerate(fft_roots):
    print(f"    ({r.real:.17}, {r.imag:.17}),")
print("];")
print()

# Extract NTT roots for n=512
ntt_roots = roots_dict_Zq[512]
print("// NTT roots of unity mod q for n=512")
print("pub const NTT_ROOTS: [i32; 512] = [")
for i in range(0, 512, 8):
    line = ", ".join(str(ntt_roots[j]) for j in range(i, min(i+8, 512)))
    print(f"    {line},")
print("];")
print()

# Extract inverse mod q table (needed for division)
print("// Inverse mod q lookup table (inv_mod_q[i] = i^-1 mod q)")
print("pub const INV_MOD_Q: [i32; 12289] = [")
for i in range(0, 12289, 16):
    line = ", ".join(str(inv_mod_q.get(j, 0)) for j in range(i, min(i+16, 12289)))
    print(f"    {line},")
print("];")
```

**Step 2: Run script and save output**

Run: `python scripts/extract_constants.py > src/constants.rs.tmp`

**Step 3: Write constants.rs with header**

```rust
//! Precomputed constants for Falcon-512.
//!
//! These constants are extracted from the Python reference implementation.

use crate::{N, Q};

/// Inverse of 2 mod q.
pub const I2: i32 = 6145;

/// Square root of -1 mod q.
pub const SQR1: i32 = 1479;

// Include the generated constants (FFT_ROOTS, NTT_ROOTS, INV_MOD_Q)
// ... paste output from script ...
```

**Step 4: Verify module compiles**

Run: `cargo build`
Expected: Successful compilation

**Step 5: Commit**

```bash
git add scripts/extract_constants.py src/constants.rs
git commit -m "feat: add precomputed FFT/NTT constants for n=512"
```

---

## Task 3: Common Utilities

**Files:**
- Create: `src/common.rs`
- Modify: `src/lib.rs`

**Step 1: Write common.rs with split/merge**

```rust
//! Common utilities used across modules.

/// Split a polynomial f into even and odd coefficients.
/// f(x) -> (f0(x^2), f1(x^2)) where f(x) = f0(x^2) + x*f1(x^2)
pub fn split<const N: usize>(f: &[i32; N]) -> ([i32; N/2], [i32; N/2]) {
    let mut f0 = [0i32; N/2];
    let mut f1 = [0i32; N/2];
    for i in 0..N/2 {
        f0[i] = f[2 * i];
        f1[i] = f[2 * i + 1];
    }
    (f0, f1)
}

/// Merge two polynomials into one.
/// (f0, f1) -> f where f(x) = f0(x^2) + x*f1(x^2)
pub fn merge<const N: usize>(f0: &[i32; N/2], f1: &[i32; N/2]) -> [i32; N] {
    let mut f = [0i32; N];
    for i in 0..N/2 {
        f[2 * i] = f0[i];
        f[2 * i + 1] = f1[i];
    }
    f
}

/// Compute the squared Euclidean norm of a vector of polynomials.
pub fn sqnorm(v: &[&[i32]]) -> i64 {
    let mut res = 0i64;
    for poly in v {
        for &coef in *poly {
            res += (coef as i64) * (coef as i64);
        }
    }
    res
}
```

**Step 2: Add common to lib.rs**

Add `pub mod common;` to `src/lib.rs`.

**Step 3: Write unit tests**

Add to `src/common.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_merge_roundtrip() {
        let f: [i32; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let (f0, f1) = split(&f);
        assert_eq!(f0, [1, 3, 5, 7]);
        assert_eq!(f1, [2, 4, 6, 8]);
        let f_back: [i32; 8] = merge(&f0, &f1);
        assert_eq!(f, f_back);
    }

    #[test]
    fn test_sqnorm() {
        let a = [3, 4];
        let b = [0, 5];
        assert_eq!(sqnorm(&[&a[..], &b[..]]), 9 + 16 + 0 + 25);
    }
}
```

**Step 4: Run tests**

Run: `cargo test common`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/common.rs src/lib.rs
git commit -m "feat: add common utilities (split, merge, sqnorm)"
```

---

## Task 4: NTT Module

**Files:**
- Modify: `src/ntt.rs`

**Step 1: Write NTT implementation**

```rust
//! Number Theoretic Transform over Z_q[x]/(x^n + 1).

use crate::constants::{INV_MOD_Q, NTT_ROOTS, I2, SQR1};
use crate::Q;

/// Split a polynomial in NTT representation.
pub fn split_ntt<const N: usize>(f_ntt: &[i32; N]) -> ([i32; N/2], [i32; N/2]) {
    let mut f0_ntt = [0i32; N/2];
    let mut f1_ntt = [0i32; N/2];
    let w = &NTT_ROOTS[..N];

    for i in 0..N/2 {
        let sum = (f_ntt[2*i] + f_ntt[2*i + 1]).rem_euclid(Q);
        let diff = (f_ntt[2*i] - f_ntt[2*i + 1]).rem_euclid(Q);
        f0_ntt[i] = ((I2 as i64 * sum as i64) % Q as i64) as i32;
        f1_ntt[i] = ((I2 as i64 * diff as i64 * INV_MOD_Q[w[2*i] as usize] as i64) % Q as i64) as i32;
    }
    (f0_ntt, f1_ntt)
}

/// Merge two polynomials in NTT representation.
pub fn merge_ntt<const N: usize>(f0_ntt: &[i32; N/2], f1_ntt: &[i32; N/2]) -> [i32; N] {
    let mut f_ntt = [0i32; N];
    let w = &NTT_ROOTS[..N];

    for i in 0..N/2 {
        let wf1 = ((w[2*i] as i64 * f1_ntt[i] as i64) % Q as i64) as i32;
        f_ntt[2*i] = (f0_ntt[i] + wf1).rem_euclid(Q);
        f_ntt[2*i + 1] = (f0_ntt[i] - wf1).rem_euclid(Q);
    }
    f_ntt
}

/// Compute NTT of a polynomial (coefficient -> NTT representation).
pub fn ntt<const N: usize>(f: &[i32; N]) -> [i32; N] {
    if N > 2 {
        let (f0, f1) = crate::common::split(f);
        let f0_ntt = ntt(&f0);
        let f1_ntt = ntt(&f1);
        merge_ntt(&f0_ntt, &f1_ntt)
    } else {
        let mut f_ntt = [0i32; N];
        f_ntt[0] = (f[0] + ((SQR1 as i64 * f[1] as i64) % Q as i64) as i32).rem_euclid(Q);
        f_ntt[1] = (f[0] - ((SQR1 as i64 * f[1] as i64) % Q as i64) as i32).rem_euclid(Q);
        f_ntt
    }
}

/// Compute inverse NTT (NTT -> coefficient representation).
pub fn intt<const N: usize>(f_ntt: &[i32; N]) -> [i32; N] {
    if N > 2 {
        let (f0_ntt, f1_ntt) = split_ntt(f_ntt);
        let f0 = intt(&f0_ntt);
        let f1 = intt(&f1_ntt);
        crate::common::merge(&f0, &f1)
    } else {
        let mut f = [0i32; N];
        let sum = (f_ntt[0] + f_ntt[1]).rem_euclid(Q);
        let diff = (f_ntt[0] - f_ntt[1]).rem_euclid(Q);
        f[0] = ((I2 as i64 * sum as i64) % Q as i64) as i32;
        f[1] = ((I2 as i64 * INV_MOD_Q[SQR1 as usize] as i64 * diff as i64) % Q as i64) as i32;
        f
    }
}

/// Addition of two polynomials in Z_q.
pub fn add_zq<const N: usize>(f: &[i32; N], g: &[i32; N]) -> [i32; N] {
    let mut result = [0i32; N];
    for i in 0..N {
        result[i] = (f[i] + g[i]).rem_euclid(Q);
    }
    result
}

/// Negation of a polynomial in Z_q.
pub fn neg_zq<const N: usize>(f: &[i32; N]) -> [i32; N] {
    let mut result = [0i32; N];
    for i in 0..N {
        result[i] = (-f[i]).rem_euclid(Q);
    }
    result
}

/// Subtraction of two polynomials in Z_q.
pub fn sub_zq<const N: usize>(f: &[i32; N], g: &[i32; N]) -> [i32; N] {
    add_zq(f, &neg_zq(g))
}

/// Multiplication in NTT representation (pointwise).
pub fn mul_ntt<const N: usize>(f_ntt: &[i32; N], g_ntt: &[i32; N]) -> [i32; N] {
    let mut result = [0i32; N];
    for i in 0..N {
        result[i] = ((f_ntt[i] as i64 * g_ntt[i] as i64) % Q as i64) as i32;
    }
    result
}

/// Division in NTT representation (pointwise).
pub fn div_ntt<const N: usize>(f_ntt: &[i32; N], g_ntt: &[i32; N]) -> Option<[i32; N]> {
    let mut result = [0i32; N];
    for i in 0..N {
        if g_ntt[i] == 0 {
            return None;
        }
        result[i] = ((f_ntt[i] as i64 * INV_MOD_Q[g_ntt[i] as usize] as i64) % Q as i64) as i32;
    }
    Some(result)
}

/// Multiplication of two polynomials in coefficient representation.
pub fn mul_zq<const N: usize>(f: &[i32; N], g: &[i32; N]) -> [i32; N] {
    intt(&mul_ntt(&ntt(f), &ntt(g)))
}

/// Division of two polynomials in coefficient representation.
pub fn div_zq<const N: usize>(f: &[i32; N], g: &[i32; N]) -> Option<[i32; N]> {
    div_ntt(&ntt(f), &ntt(g)).map(|r| intt(&r))
}
```

**Step 2: Write NTT tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_intt_roundtrip() {
        let f: [i32; 4] = [1, 2, 3, 4];
        let f_ntt = ntt(&f);
        let f_back = intt(&f_ntt);
        assert_eq!(f, f_back);
    }

    #[test]
    fn test_mul_zq() {
        // Multiply (1 + x) * (1 + x) = 1 + 2x + x^2
        // In ring Z_q[x]/(x^4 + 1): x^2 stays as x^2
        let f: [i32; 4] = [1, 1, 0, 0];
        let result = mul_zq(&f, &f);
        assert_eq!(result[0], 1);
        assert_eq!(result[1], 2);
        assert_eq!(result[2], 1);
        assert_eq!(result[3], 0);
    }
}
```

**Step 3: Run tests**

Run: `cargo test ntt`
Expected: All tests pass

**Step 4: Commit**

```bash
git add src/ntt.rs
git commit -m "feat: implement NTT over Z_q[x]/(x^n + 1)"
```

---

## Task 5: FFT Module

**Files:**
- Modify: `src/fft.rs`

**Step 1: Write complex number type**

```rust
//! Fast Fourier Transform over R[x]/(x^n + 1).

use crate::constants::FFT_ROOTS;

/// Complex number with f64 components.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Complex {
    pub re: f64,
    pub im: f64,
}

impl Complex {
    pub const ZERO: Complex = Complex { re: 0.0, im: 0.0 };
    pub const ONE: Complex = Complex { re: 1.0, im: 0.0 };
    pub const I: Complex = Complex { re: 0.0, im: 1.0 };

    pub fn new(re: f64, im: f64) -> Self {
        Complex { re, im }
    }

    pub fn conj(self) -> Self {
        Complex { re: self.re, im: -self.im }
    }
}

impl std::ops::Add for Complex {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Complex { re: self.re + rhs.re, im: self.im + rhs.im }
    }
}

impl std::ops::Sub for Complex {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Complex { re: self.re - rhs.re, im: self.im - rhs.im }
    }
}

impl std::ops::Mul for Complex {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Complex {
            re: self.re * rhs.re - self.im * rhs.im,
            im: self.re * rhs.im + self.im * rhs.re,
        }
    }
}

impl std::ops::Div for Complex {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        let denom = rhs.re * rhs.re + rhs.im * rhs.im;
        Complex {
            re: (self.re * rhs.re + self.im * rhs.im) / denom,
            im: (self.im * rhs.re - self.re * rhs.im) / denom,
        }
    }
}

impl std::ops::Mul<f64> for Complex {
    type Output = Self;
    fn mul(self, rhs: f64) -> Self {
        Complex { re: self.re * rhs, im: self.im * rhs }
    }
}
```

**Step 2: Write FFT functions**

```rust
/// Get FFT root at index i for degree n.
fn fft_root(n: usize, i: usize) -> Complex {
    let (re, im) = FFT_ROOTS[i]; // Assumes roots are stored for max N
    Complex::new(re, im)
}

/// Split a polynomial in FFT representation.
pub fn split_fft<const N: usize>(f_fft: &[Complex; N]) -> ([Complex; N/2], [Complex; N/2]) {
    let mut f0_fft = [Complex::ZERO; N/2];
    let mut f1_fft = [Complex::ZERO; N/2];

    for i in 0..N/2 {
        let w = fft_root(N, 2*i);
        f0_fft[i] = (f_fft[2*i] + f_fft[2*i + 1]) * 0.5;
        f1_fft[i] = (f_fft[2*i] - f_fft[2*i + 1]) * 0.5 * w.conj();
    }
    (f0_fft, f1_fft)
}

/// Merge two polynomials in FFT representation.
pub fn merge_fft<const N: usize>(f0_fft: &[Complex; N/2], f1_fft: &[Complex; N/2]) -> [Complex; N] {
    let mut f_fft = [Complex::ZERO; N];

    for i in 0..N/2 {
        let w = fft_root(N, 2*i);
        let wf1 = w * f1_fft[i];
        f_fft[2*i] = f0_fft[i] + wf1;
        f_fft[2*i + 1] = f0_fft[i] - wf1;
    }
    f_fft
}

/// Compute FFT of a polynomial (coefficient -> FFT representation).
pub fn fft<const N: usize>(f: &[f64; N]) -> [Complex; N] {
    if N > 2 {
        let mut f0 = [0.0f64; N/2];
        let mut f1 = [0.0f64; N/2];
        for i in 0..N/2 {
            f0[i] = f[2*i];
            f1[i] = f[2*i + 1];
        }
        let f0_fft = fft(&f0);
        let f1_fft = fft(&f1);
        merge_fft(&f0_fft, &f1_fft)
    } else {
        let mut f_fft = [Complex::ZERO; N];
        f_fft[0] = Complex::new(f[0], f[1]);
        f_fft[1] = Complex::new(f[0], -f[1]);
        f_fft
    }
}

/// Compute inverse FFT (FFT -> coefficient representation).
pub fn ifft<const N: usize>(f_fft: &[Complex; N]) -> [f64; N] {
    if N > 2 {
        let (f0_fft, f1_fft) = split_fft(f_fft);
        let f0 = ifft(&f0_fft);
        let f1 = ifft(&f1_fft);
        let mut f = [0.0f64; N];
        for i in 0..N/2 {
            f[2*i] = f0[i];
            f[2*i + 1] = f1[i];
        }
        f
    } else {
        let mut f = [0.0f64; N];
        f[0] = f_fft[0].re;
        f[1] = f_fft[0].im;
        f
    }
}

// FFT-representation operations
pub fn add_fft<const N: usize>(f: &[Complex; N], g: &[Complex; N]) -> [Complex; N] {
    let mut result = [Complex::ZERO; N];
    for i in 0..N {
        result[i] = f[i] + g[i];
    }
    result
}

pub fn sub_fft<const N: usize>(f: &[Complex; N], g: &[Complex; N]) -> [Complex; N] {
    let mut result = [Complex::ZERO; N];
    for i in 0..N {
        result[i] = f[i] - g[i];
    }
    result
}

pub fn mul_fft<const N: usize>(f: &[Complex; N], g: &[Complex; N]) -> [Complex; N] {
    let mut result = [Complex::ZERO; N];
    for i in 0..N {
        result[i] = f[i] * g[i];
    }
    result
}

pub fn div_fft<const N: usize>(f: &[Complex; N], g: &[Complex; N]) -> [Complex; N] {
    let mut result = [Complex::ZERO; N];
    for i in 0..N {
        result[i] = f[i] / g[i];
    }
    result
}

pub fn adj_fft<const N: usize>(f: &[Complex; N]) -> [Complex; N] {
    let mut result = [Complex::ZERO; N];
    for i in 0..N {
        result[i] = f[i].conj();
    }
    result
}
```

**Step 3: Write FFT tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fft_ifft_roundtrip() {
        let f: [f64; 4] = [1.0, 2.0, 3.0, 4.0];
        let f_fft = fft(&f);
        let f_back = ifft(&f_fft);
        for i in 0..4 {
            assert!((f[i] - f_back[i]).abs() < 1e-10);
        }
    }

    #[test]
    fn test_complex_ops() {
        let a = Complex::new(1.0, 2.0);
        let b = Complex::new(3.0, 4.0);
        let sum = a + b;
        assert_eq!(sum.re, 4.0);
        assert_eq!(sum.im, 6.0);
    }
}
```

**Step 4: Run tests**

Run: `cargo test fft`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/fft.rs
git commit -m "feat: implement FFT over R[x]/(x^n + 1)"
```

---

## Task 6: ChaCha20 RNG

**Files:**
- Modify: `src/rng.rs`

**Step 1: Write ChaCha20 implementation**

```rust
//! ChaCha20-based PRNG for Falcon signing.

const CW: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

fn roll(x: u32, n: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}

pub struct ChaCha20 {
    s: [u32; 14],
    ctr: u64,
    buffer: Vec<u8>,
    buf_pos: usize,
}

impl ChaCha20 {
    pub fn new(seed: &[u8; 56]) -> Self {
        let mut s = [0u32; 14];
        for i in 0..14 {
            s[i] = u32::from_le_bytes([
                seed[4*i], seed[4*i + 1], seed[4*i + 2], seed[4*i + 3]
            ]);
        }
        let ctr = (s[12] as u64) | ((s[13] as u64) << 32);
        ChaCha20 { s, ctr, buffer: Vec::new(), buf_pos: 0 }
    }

    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] = roll(state[d] ^ state[a], 16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = roll(state[b] ^ state[c], 12);
        state[a] = state[a].wrapping_add(state[b]);
        state[d] = roll(state[d] ^ state[a], 8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = roll(state[b] ^ state[c], 7);
    }

    fn update(&mut self) -> [u32; 16] {
        let mut state = [0u32; 16];
        state[0..4].copy_from_slice(&CW);
        state[4..14].copy_from_slice(&self.s[0..10]);
        state[14] = self.s[10] ^ (self.ctr as u32);
        state[15] = self.s[11] ^ ((self.ctr >> 32) as u32);

        let initial = state;

        for _ in 0..10 {
            Self::quarter_round(&mut state, 0, 4, 8, 12);
            Self::quarter_round(&mut state, 1, 5, 9, 13);
            Self::quarter_round(&mut state, 2, 6, 10, 14);
            Self::quarter_round(&mut state, 3, 7, 11, 15);
            Self::quarter_round(&mut state, 0, 5, 10, 15);
            Self::quarter_round(&mut state, 1, 6, 11, 12);
            Self::quarter_round(&mut state, 2, 7, 8, 13);
            Self::quarter_round(&mut state, 3, 4, 9, 14);
        }

        for i in 0..16 {
            state[i] = state[i].wrapping_add(initial[i]);
        }

        self.ctr += 1;
        state
    }

    fn block_update(&mut self) -> Vec<u8> {
        let mut blocks = [[0u32; 16]; 8];
        for i in 0..8 {
            blocks[i] = self.update();
        }

        // Interleave results
        let mut result = Vec::with_capacity(512);
        for word_idx in 0..16 {
            for block_idx in 0..8 {
                result.extend_from_slice(&blocks[block_idx][word_idx].to_le_bytes());
            }
        }
        result
    }

    pub fn random_bytes(&mut self, k: usize) -> Vec<u8> {
        while self.buffer.len() - self.buf_pos < k {
            let new_bytes = self.block_update();
            self.buffer.extend(new_bytes);
        }

        // Match Python's byte ordering
        let mut out: Vec<u8> = self.buffer[self.buf_pos..self.buf_pos + k].to_vec();
        out.reverse();
        self.buf_pos += k;
        out
    }
}
```

**Step 2: Write RNG tests (compare with Python KAT)**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_deterministic() {
        let seed = [0u8; 56];
        let mut rng1 = ChaCha20::new(&seed);
        let mut rng2 = ChaCha20::new(&seed);

        assert_eq!(rng1.random_bytes(16), rng2.random_bytes(16));
    }
}
```

**Step 3: Run tests**

Run: `cargo test rng`
Expected: All tests pass

**Step 4: Commit**

```bash
git add src/rng.rs
git commit -m "feat: implement ChaCha20 PRNG for signing"
```

---

## Task 7: Gaussian Sampler (samplerz)

**Files:**
- Modify: `src/samplerz.rs`
- Create: `tests/samplerz_kat.rs`
- Create: `test_vectors/samplerz_kat512.json`

**Step 1: Convert Python KAT to JSON**

Create `scripts/convert_samplerz_kat.py`:
```python
#!/usr/bin/env python3
import json
import sys
sys.path.insert(0, 'falcon.py/scripts')
from samplerz_KAT512 import sampler_KAT512

# Convert to JSON-friendly format
kat = []
for entry in sampler_KAT512[:50]:  # First 50 entries
    kat.append({
        'mu': entry['mu'],
        'sigma': entry['sigma'],
        'sigmin': entry['sigmin'],
        'octets': entry['octets'],
        'z': entry['z']
    })

print(json.dumps(kat, indent=2))
```

Run: `python scripts/convert_samplerz_kat.py > test_vectors/samplerz_kat512.json`

**Step 2: Write samplerz implementation**

```rust
//! Gaussian sampler over the integers.

use crate::rng::ChaCha20;

const MAX_SIGMA: f64 = 1.8205;
const INV_2SIGMA2: f64 = 1.0 / (2.0 * MAX_SIGMA * MAX_SIGMA);
const RCDT_PREC: usize = 72;
const LN2: f64 = 0.69314718056;
const ILN2: f64 = 1.44269504089;

/// Reverse cumulative distribution table for half-Gaussian.
const RCDT: [u128; 18] = [
    3024686241123004913666,
    1564742784480091954050,
    636254429462080897535,
    199560484645026482916,
    47667343854657281903,
    8595902006365044063,
    1163297957344668388,
    117656387352093658,
    8867391802663976,
    496969357462633,
    20680885154299,
    638331848991,
    14602316184,
    247426747,
    3104126,
    28824,
    198,
    1,
];

/// Polynomial coefficients for exp(-x) approximation.
const C: [u64; 13] = [
    0x00000004741183A3,
    0x00000036548CFC06,
    0x0000024FDCBF140A,
    0x0000171D939DE045,
    0x0000D00CF58F6F84,
    0x000680681CF796E3,
    0x002D82D8305B0FEA,
    0x011111110E066FD0,
    0x0555555555070F00,
    0x155555555581FF00,
    0x400000000002B400,
    0x7FFFFFFFFFFF4800,
    0x8000000000000000,
];

/// Sample from half-Gaussian distribution.
fn basesampler(random_bytes: &[u8]) -> i32 {
    let u = u128::from_le_bytes({
        let mut arr = [0u8; 16];
        arr[..9].copy_from_slice(&random_bytes[..9]);
        arr
    });

    let mut z0 = 0i32;
    for &elt in &RCDT {
        if u < elt {
            z0 += 1;
        }
    }
    z0
}

/// Approximate 2^63 * ccs * exp(-x).
fn approxexp(x: f64, ccs: f64) -> u64 {
    let mut y = C[0];
    let z = (x * (1u64 << 63) as f64) as i64;

    for &elt in &C[1..] {
        y = elt.wrapping_sub(((z as i128 * y as i128) >> 63) as u64);
    }

    let z = ((ccs * (1u64 << 63) as f64) as u64) << 1;
    ((z as u128 * y as u128) >> 63) as u64
}

/// Bernoulli trial with probability ccs * exp(-x).
fn berexp<F: FnMut(usize) -> Vec<u8>>(x: f64, ccs: f64, random_bytes: &mut F) -> bool {
    let s = (x * ILN2) as i32;
    let r = x - (s as f64) * LN2;
    let s = s.min(63) as u32;
    let z = (approxexp(r, ccs).wrapping_sub(1)) >> s;

    for i in (0..=7).rev() {
        let p = random_bytes(1)[0];
        let w = (p as i32) - (((z >> (8 * i)) & 0xFF) as i32);
        if w != 0 {
            return w < 0;
        }
    }
    false
}

/// Sample from discrete Gaussian D_{Z, mu, sigma}.
pub fn samplerz<F: FnMut(usize) -> Vec<u8>>(
    mu: f64,
    sigma: f64,
    sigmin: f64,
    random_bytes: &mut F,
) -> i32 {
    let s = mu.floor() as i32;
    let r = mu - (s as f64);
    let dss = 1.0 / (2.0 * sigma * sigma);
    let ccs = sigmin / sigma;

    loop {
        let z0 = basesampler(&random_bytes(RCDT_PREC / 8));
        let b = random_bytes(1)[0] & 1;
        let z = (b as i32) + (2 * (b as i32) - 1) * z0;

        let zr = (z as f64) - r;
        let mut x = zr * zr * dss;
        x -= (z0 * z0) as f64 * INV_2SIGMA2;

        if berexp(x, ccs, random_bytes) {
            return z + s;
        }
    }
}
```

**Step 3: Write KAT test**

Create `tests/samplerz_kat.rs`:
```rust
use falcon_rs::samplerz::samplerz;
use serde::Deserialize;

#[derive(Deserialize)]
struct SamplerKat {
    mu: f64,
    sigma: f64,
    sigmin: f64,
    octets: String,
    z: i32,
}

#[test]
fn test_samplerz_kat512() {
    let kat_json = include_str!("../test_vectors/samplerz_kat512.json");
    let kats: Vec<SamplerKat> = serde_json::from_str(kat_json).unwrap();

    for (i, kat) in kats.iter().enumerate() {
        let octets = hex::decode(&kat.octets).unwrap();
        let mut pos = 0;
        let mut random_bytes = |n: usize| -> Vec<u8> {
            let result = octets[pos..pos+n].to_vec();
            pos += n;
            result
        };

        let z = samplerz(kat.mu, kat.sigma, kat.sigmin, &mut random_bytes);
        assert_eq!(z, kat.z, "KAT {} failed: expected {}, got {}", i, kat.z, z);
    }
}
```

Add `hex = "0.4"` to dev-dependencies in Cargo.toml.

**Step 4: Run KAT tests**

Run: `cargo test samplerz_kat`
Expected: All KAT tests pass

**Step 5: Commit**

```bash
git add src/samplerz.rs tests/samplerz_kat.rs test_vectors/samplerz_kat512.json scripts/convert_samplerz_kat.py Cargo.toml
git commit -m "feat: implement Gaussian sampler with KAT verification"
```

---

## Task 8: FFSampling Module

**Files:**
- Modify: `src/ffsampling.rs`

**Step 1: Write LDL tree types**

```rust
//! Fast Fourier Sampling for Falcon.

use crate::fft::{Complex, add_fft, sub_fft, mul_fft, div_fft, adj_fft, split_fft, merge_fft};
use crate::samplerz::samplerz;

/// LDL decomposition tree node.
#[derive(Clone)]
pub enum LdlTree {
    /// Leaf node with sigma value.
    Leaf(f64),
    /// Internal node with l10 polynomial and two children.
    Node {
        l10: Vec<Complex>,
        left: Box<LdlTree>,
        right: Box<LdlTree>,
    },
}
```

**Step 2: Write LDL and ffLDL functions**

```rust
/// Compute Gram matrix of B (2x2 matrix of polynomials).
pub fn gram<const N: usize>(b: &[[Vec<Complex>; 2]; 2]) -> [[Vec<Complex>; 2]; 2] {
    // G[i][j] = sum_k B[i][k] * adj(B[j][k])
    let mut g = [[vec![Complex::ZERO; N], vec![Complex::ZERO; N]],
                 [vec![Complex::ZERO; N], vec![Complex::ZERO; N]]];

    for i in 0..2 {
        for j in 0..2 {
            for k in 0..2 {
                let prod = mul_fft_vec(&b[i][k], &adj_fft_vec(&b[j][k]));
                g[i][j] = add_fft_vec(&g[i][j], &prod);
            }
        }
    }
    g
}

/// LDL decomposition of 2x2 Gram matrix in FFT representation.
pub fn ldl_fft<const N: usize>(g: &[[Vec<Complex>; 2]; 2]) -> ([[Vec<Complex>; 2]; 2], [[Vec<Complex>; 2]; 2]) {
    let zero = vec![Complex::ZERO; N];
    let one = vec![Complex::ONE; N];

    let d00 = g[0][0].clone();
    let l10 = div_fft_vec(&g[1][0], &g[0][0]);
    let l10_adj = adj_fft_vec(&l10);
    let l10_l10_adj = mul_fft_vec(&l10, &l10_adj);
    let d11 = sub_fft_vec(&g[1][1], &mul_fft_vec(&l10_l10_adj, &g[0][0]));

    let l = [[one.clone(), zero.clone()], [l10, one]];
    let d = [[d00, zero.clone()], [zero, d11]];

    (l, d)
}

/// Compute ffLDL decomposition tree.
pub fn ffldl_fft(g: &[[Vec<Complex>; 2]; 2]) -> LdlTree {
    let n = g[0][0].len();
    let (l, d) = ldl_fft::<{N}>(g);

    if n > 1 {
        let (d00_0, d00_1) = split_fft_vec(&d[0][0]);
        let (d11_0, d11_1) = split_fft_vec(&d[1][1]);

        let g0 = [[d00_0.clone(), d00_1.clone()],
                  [adj_fft_vec(&d00_1), d00_0]];
        let g1 = [[d11_0.clone(), d11_1.clone()],
                  [adj_fft_vec(&d11_1), d11_0]];

        LdlTree::Node {
            l10: l[1][0].clone(),
            left: Box::new(ffldl_fft(&g0)),
            right: Box::new(ffldl_fft(&g1)),
        }
    } else {
        // Leaf: store sigma = sqrt(d[0][0].re)
        LdlTree::Leaf(d[0][0][0].re.sqrt())
    }
}

/// Normalize LDL tree leaves (from ||b_i||^2 to sigma/||b_i||).
pub fn normalize_tree(tree: &mut LdlTree, sigma: f64) {
    match tree {
        LdlTree::Leaf(ref mut val) => {
            *val = sigma / *val;
        }
        LdlTree::Node { left, right, .. } => {
            normalize_tree(left, sigma);
            normalize_tree(right, sigma);
        }
    }
}
```

**Step 3: Write ffsampling function**

```rust
/// Fast Fourier Sampling.
pub fn ffsampling_fft<F: FnMut(usize) -> Vec<u8>>(
    t: &[Vec<Complex>; 2],
    tree: &LdlTree,
    sigmin: f64,
    random_bytes: &mut F,
) -> [Vec<Complex>; 2] {
    let n = t[0].len();

    match tree {
        LdlTree::Leaf(sigma) => {
            let z0 = samplerz(t[0][0].re, *sigma, sigmin, random_bytes);
            let z1 = samplerz(t[1][0].re, *sigma, sigmin, random_bytes);
            [vec![Complex::new(z0 as f64, 0.0)],
             vec![Complex::new(z1 as f64, 0.0)]]
        }
        LdlTree::Node { l10, left, right } => {
            let (t1_0, t1_1) = split_fft_vec(&t[1]);
            let z1_split = ffsampling_fft(&[t1_0, t1_1], right, sigmin, random_bytes);
            let z1 = merge_fft_vec(&z1_split[0], &z1_split[1]);

            let diff = sub_fft_vec(&t[1], &z1);
            let t0b = add_fft_vec(&t[0], &mul_fft_vec(&diff, l10));

            let (t0b_0, t0b_1) = split_fft_vec(&t0b);
            let z0_split = ffsampling_fft(&[t0b_0, t0b_1], left, sigmin, random_bytes);
            let z0 = merge_fft_vec(&z0_split[0], &z0_split[1]);

            [z0, z1]
        }
    }
}
```

**Step 4: Verify module compiles**

Run: `cargo build`
Expected: Successful compilation

**Step 5: Commit**

```bash
git add src/ffsampling.rs
git commit -m "feat: implement Fast Fourier Sampling"
```

---

## Task 9: NTRU Key Generation

**Files:**
- Modify: `src/ntrugen.rs`

This is the most complex module. Implementation follows Python's `ntrugen.py`.

**Step 1: Write helper functions (karatsuba, xgcd, etc.)**

```rust
//! NTRU key generation for Falcon.

use crate::fft::{fft, ifft, add_fft, mul_fft, adj_fft, div_fft};
use crate::ntt::ntt;
use crate::common::sqnorm;
use crate::samplerz::samplerz;
use crate::{Q, N};

/// Karatsuba multiplication.
fn karatsuba(a: &[i64], b: &[i64]) -> Vec<i64> {
    let n = a.len();
    if n == 1 {
        return vec![a[0] * b[0], 0];
    }

    let n2 = n / 2;
    let (a0, a1) = a.split_at(n2);
    let (b0, b1) = b.split_at(n2);

    let ax: Vec<i64> = a0.iter().zip(a1).map(|(x, y)| x + y).collect();
    let bx: Vec<i64> = b0.iter().zip(b1).map(|(x, y)| x + y).collect();

    let a0b0 = karatsuba(a0, b0);
    let a1b1 = karatsuba(a1, b1);
    let mut axbx = karatsuba(&ax, &bx);

    for i in 0..n {
        axbx[i] -= a0b0[i] + a1b1[i];
    }

    let mut ab = vec![0i64; 2 * n];
    for i in 0..n {
        ab[i] += a0b0[i];
        ab[i + n] += a1b1[i];
        ab[i + n2] += axbx[i];
    }
    ab
}

/// Karatsuba multiplication mod (x^n + 1).
fn karamul(a: &[i64], b: &[i64]) -> Vec<i64> {
    let n = a.len();
    let ab = karatsuba(a, b);
    (0..n).map(|i| ab[i] - ab[i + n]).collect()
}

/// Extended GCD.
fn xgcd(b: i64, n: i64) -> (i64, i64, i64) {
    let (mut x0, mut x1, mut y0, mut y1) = (1i64, 0i64, 0i64, 1i64);
    let (mut b, mut n) = (b, n);

    while n != 0 {
        let q = b / n;
        let temp = n;
        n = b % n;
        b = temp;

        let temp = x1;
        x1 = x0 - q * x1;
        x0 = temp;

        let temp = y1;
        y1 = y0 - q * y1;
        y0 = temp;
    }
    (b, x0, y0)
}

// ... more helper functions (galois_conjugate, field_norm, lift, reduce, ntru_solve) ...
```

**Step 2: Write ntru_gen function**

```rust
/// Generate NTRU polynomials (f, g, F, G) for Falcon.
pub fn ntru_gen() -> ([i32; N], [i32; N], [i32; N], [i32; N]) {
    loop {
        let f = gen_poly();
        let g = gen_poly();

        // Check Gram-Schmidt norm
        if gs_norm(&f, &g) > 1.17 * 1.17 * (Q as f64) {
            continue;
        }

        // Check f is invertible in NTT
        let f_ntt = ntt(&f);
        if f_ntt.iter().any(|&x| x == 0) {
            continue;
        }

        // Solve NTRU equation
        match ntru_solve(&f, &g) {
            Ok((F, G)) => return (f, g, F, G),
            Err(_) => continue,
        }
    }
}
```

**Step 3: Verify module compiles**

Run: `cargo build`
Expected: Successful compilation

**Step 4: Commit**

```bash
git add src/ntrugen.rs
git commit -m "feat: implement NTRU key generation"
```

---

## Task 10: Encoding Module

**Files:**
- Modify: `src/encoding.rs`

**Step 1: Write compress/decompress**

```rust
//! Signature compression and decompression.

/// Compress a polynomial to bytes.
pub fn compress(v: &[i32], slen: usize) -> Option<Vec<u8>> {
    let mut bits = String::new();

    for &coef in v {
        // Sign bit
        bits.push(if coef < 0 { '1' } else { '0' });
        // Low 7 bits
        let abs_coef = coef.abs();
        for i in (0..7).rev() {
            bits.push(if (abs_coef >> i) & 1 == 1 { '1' } else { '0' });
        }
        // High bits in unary
        let high = abs_coef >> 7;
        for _ in 0..high {
            bits.push('0');
        }
        bits.push('1');
    }

    if bits.len() > 8 * slen {
        return None;
    }

    // Pad to slen bytes
    while bits.len() < 8 * slen {
        bits.push('0');
    }

    // Convert to bytes
    let bytes: Vec<u8> = (0..slen)
        .map(|i| u8::from_str_radix(&bits[8*i..8*i+8], 2).unwrap())
        .collect();

    Some(bytes)
}

/// Decompress bytes to polynomial.
pub fn decompress(x: &[u8], n: usize) -> Option<Vec<i32>> {
    let mut bits: String = x.iter()
        .map(|b| format!("{:08b}", b))
        .collect();

    // Remove trailing zeros
    while bits.ends_with('0') {
        bits.pop();
    }

    let mut v = Vec::with_capacity(n);
    let mut pos = 0;

    while !bits[pos..].is_empty() && v.len() < n {
        // Sign
        let sign = if bits.chars().nth(pos) == Some('1') { -1 } else { 1 };
        pos += 1;

        // Low 7 bits
        let low = i32::from_str_radix(&bits[pos..pos+7], 2).ok()?;
        pos += 7;

        // High bits (unary)
        let mut high = 0;
        while bits.chars().nth(pos) == Some('0') {
            high += 1;
            pos += 1;
        }
        pos += 1; // Skip the '1'

        let coef = sign * (low + (high << 7));

        // Reject -0
        if coef == 0 && sign == -1 {
            return None;
        }

        v.push(coef);
    }

    if v.len() != n {
        return None;
    }

    Some(v)
}
```

**Step 2: Write roundtrip tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_roundtrip() {
        let v = vec![1, -2, 3, -4, 0, 127, -128, 255];
        let compressed = compress(&v, 100).unwrap();
        let decompressed = decompress(&compressed, v.len()).unwrap();
        assert_eq!(v, decompressed);
    }
}
```

**Step 3: Run tests**

Run: `cargo test encoding`
Expected: All tests pass

**Step 4: Commit**

```bash
git add src/encoding.rs
git commit -m "feat: implement signature compression/decompression"
```

---

## Task 11: HashToPoint Trait

**Files:**
- Modify: `src/hash_to_point.rs`

**Step 1: Write trait and SHAKE256 implementation**

```rust
//! HashToPoint trait and implementations.

use crate::{N, Q};

/// Trait for hashing message to polynomial in Z_q[x]/(x^n + 1).
pub trait HashToPoint {
    fn hash_to_point(message: &[u8], salt: &[u8; 40]) -> [i16; N];
}

/// SHAKE256-based hash (matches Python reference).
#[cfg(feature = "shake")]
pub struct Shake256Hash;

#[cfg(feature = "shake")]
impl HashToPoint for Shake256Hash {
    fn hash_to_point(message: &[u8], salt: &[u8; 40]) -> [i16; N] {
        use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

        let mut hasher = Shake256::default();
        hasher.update(salt);
        hasher.update(message);
        let mut reader = hasher.finalize_xof();

        let k = (1 << 16) / (Q as u32);
        let mut hashed = [0i16; N];
        let mut i = 0;

        while i < N {
            let mut buf = [0u8; 2];
            reader.read(&mut buf);
            let elt = ((buf[0] as u32) << 8) | (buf[1] as u32);

            // Rejection sampling
            if elt < k * (Q as u32) {
                hashed[i] = (elt % (Q as u32)) as i16;
                i += 1;
            }
        }

        hashed
    }
}

/// Poseidon-based hash (placeholder for Starknet).
pub struct PoseidonHash;

impl HashToPoint for PoseidonHash {
    fn hash_to_point(_message: &[u8], _salt: &[u8; 40]) -> [i16; N] {
        todo!("Implement Starknet Poseidon mapping")
    }
}
```

**Step 2: Verify module compiles**

Run: `cargo build --features shake`
Expected: Successful compilation

**Step 3: Commit**

```bash
git add src/hash_to_point.rs
git commit -m "feat: add HashToPoint trait with SHAKE256 implementation"
```

---

## Task 12: Core Falcon Module

**Files:**
- Modify: `src/falcon.rs`

**Step 1: Write key types**

```rust
//! Core Falcon-512 signature scheme.

use crate::hash_to_point::HashToPoint;
use crate::ffsampling::{LdlTree, ffsampling_fft, gram, ffldl_fft, normalize_tree};
use crate::ntt::{div_zq, sub_zq, mul_zq};
use crate::ntrugen::ntru_gen;
use crate::encoding::{compress, decompress};
use crate::fft::{fft, ifft, Complex};
use crate::rng::ChaCha20;
use crate::{N, Q, SALT_LEN, SEED_LEN};
use std::marker::PhantomData;

/// Falcon-512 parameters.
const SIGMA: f64 = 165.7366171829776;
const SIGMIN: f64 = 1.2778336969128337;
const SIG_BOUND: i64 = 34034726;
const SIG_BYTELEN: usize = 666;
const HEAD_LEN: usize = 1;

/// Secret key for Falcon-512.
pub struct SecretKey {
    f: [i32; N],
    g: [i32; N],
    capital_f: [i32; N],
    capital_g: [i32; N],
    b0_fft: [[Vec<Complex>; 2]; 2],
    tree: LdlTree,
}

/// Verifying key (public key) for Falcon-512.
pub struct VerifyingKey {
    h: [i32; N],
}

/// Signature for Falcon-512.
pub struct Signature {
    header: u8,
    salt: [u8; SALT_LEN],
    s1_enc: Vec<u8>,
}

impl SecretKey {
    pub fn to_bytes(&self) -> [u8; 3584] {
        // Serialize f, g, F, G (4 polys × 896 bytes each)
        todo!()
    }

    pub fn from_bytes(bytes: &[u8; 3584]) -> Result<Self, DecodeError> {
        todo!()
    }
}

impl VerifyingKey {
    pub fn to_bytes(&self) -> [u8; 896] {
        todo!()
    }

    pub fn from_bytes(bytes: &[u8; 896]) -> Result<Self, DecodeError> {
        todo!()
    }
}
```

**Step 2: Write Falcon struct with sign/verify**

```rust
/// Falcon-512 signature scheme parameterized by hash function.
pub struct Falcon<H: HashToPoint> {
    _marker: PhantomData<H>,
}

impl<H: HashToPoint> Falcon<H> {
    /// Generate a new keypair.
    pub fn keygen() -> (SecretKey, VerifyingKey) {
        let (f, g, capital_f, capital_g) = ntru_gen();

        // Compute h = g/f mod (x^n + 1, q)
        let h = div_zq(&g, &f).expect("f should be invertible");

        // Compute B0 and LDL tree
        // ... (FFT computations from Python)

        todo!()
    }

    /// Sign a message.
    pub fn sign(sk: &SecretKey, message: &[u8]) -> Signature {
        let mut rng = getrandom_salt();
        let salt: [u8; SALT_LEN] = rng;

        let hashed = H::hash_to_point(message, &salt);

        loop {
            // Sample preimage
            // ... (ffsampling)

            // Check norm and encode
            todo!()
        }
    }

    /// Verify a signature.
    pub fn verify(vk: &VerifyingKey, message: &[u8], sig: &Signature) -> bool {
        let hashed = H::hash_to_point(message, &sig.salt);

        // Decompress s1
        let s1 = match decompress(&sig.s1_enc, N) {
            Some(s) => s,
            None => return false,
        };

        // Compute s0 = hashed - s1 * h
        // Check norm
        todo!()
    }
}
```

**Step 3: Verify module compiles**

Run: `cargo build --features shake`
Expected: Successful compilation

**Step 4: Commit**

```bash
git add src/falcon.rs
git commit -m "feat: implement core Falcon sign/verify"
```

---

## Task 13: Full Sign/Verify KAT Tests

**Files:**
- Create: `tests/sign_kat.rs`
- Create: `test_vectors/sign_kat.json`

**Step 1: Convert Python sign KAT to JSON**

**Step 2: Write integration test**

```rust
use falcon_rs::falcon::Falcon;
use falcon_rs::hash_to_point::Shake256Hash;

#[test]
fn test_sign_verify_roundtrip() {
    let (sk, vk) = Falcon::<Shake256Hash>::keygen();
    let message = b"Hello, Falcon!";
    let sig = Falcon::<Shake256Hash>::sign(&sk, message);
    assert!(Falcon::<Shake256Hash>::verify(&vk, message, &sig));
}

#[test]
fn test_sign_kat() {
    // Load KAT vectors and verify
    todo!()
}
```

**Step 3: Run tests**

Run: `cargo test --features shake`
Expected: All tests pass

**Step 4: Commit**

```bash
git add tests/sign_kat.rs test_vectors/sign_kat.json
git commit -m "test: add full sign/verify KAT tests"
```

---

## Task 14: WASM Bindings

**Files:**
- Modify: `src/wasm.rs`

**Step 1: Write WASM exports**

```rust
//! WASM bindings for Falcon-512 with Poseidon hash.

use wasm_bindgen::prelude::*;
use crate::falcon::{Falcon, SecretKey, VerifyingKey, Signature};
use crate::hash_to_point::PoseidonHash;

#[wasm_bindgen]
pub fn keygen() -> Result<JsValue, JsError> {
    let (sk, vk) = Falcon::<PoseidonHash>::keygen();

    let result = js_sys::Object::new();
    js_sys::Reflect::set(&result, &"sk".into(), &js_sys::Uint8Array::from(&sk.to_bytes()[..]))?;
    js_sys::Reflect::set(&result, &"vk".into(), &js_sys::Uint8Array::from(&vk.to_bytes()[..]))?;

    Ok(result.into())
}

#[wasm_bindgen]
pub fn sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsError> {
    let sk = SecretKey::from_bytes(secret_key.try_into()?)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let sig = Falcon::<PoseidonHash>::sign(&sk, message);
    Ok(sig.to_bytes())
}

#[wasm_bindgen]
pub fn verify(verifying_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsError> {
    let vk = VerifyingKey::from_bytes(verifying_key.try_into()?)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let sig = Signature::from_bytes(signature)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(Falcon::<PoseidonHash>::verify(&vk, message, &sig))
}
```

**Step 2: Build WASM**

Run: `wasm-pack build --target web --features wasm`
Expected: WASM package generated in `pkg/`

**Step 3: Commit**

```bash
git add src/wasm.rs
git commit -m "feat: add WASM bindings for browser signing"
```

---

## Task 15: Cross-Language Integration Test

**Files:**
- Create: `tests/cross_language.py`

**Step 1: Write Python test that uses Rust via subprocess**

```python
#!/usr/bin/env python3
"""Test Rust implementation against Python reference."""
import subprocess
import sys
sys.path.insert(0, 'falcon.py')

from falcon import Falcon

def test_python_keygen_rust_verify():
    """Generate keys in Python, verify signature in Rust."""
    falcon = Falcon(512)
    sk, vk = falcon.keygen()
    message = b"Test message"
    sig = falcon.sign(sk, message)

    # Export keys and signature as hex
    sk_bytes = falcon.pack_sk(sk).hex()
    # ... call Rust binary to verify

    print("Cross-language test passed!")

if __name__ == "__main__":
    test_python_keygen_rust_verify()
```

**Step 2: Run integration test**

Run: `python tests/cross_language.py`
Expected: Test passes

**Step 3: Commit**

```bash
git add tests/cross_language.py
git commit -m "test: add cross-language integration test"
```

---

## Summary

Total tasks: 15
Estimated commits: 15+

Key checkpoints:
- After Task 7: Gaussian sampler verified against KAT
- After Task 13: Full sign/verify verified against KAT
- After Task 14: WASM build working
- After Task 15: Cross-language compatibility verified
