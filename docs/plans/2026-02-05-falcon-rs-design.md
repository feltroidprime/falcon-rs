# Falcon-RS Design Document

Rust implementation of Falcon-512 signature scheme with WASM support and customizable hash function.

## Goals

1. **Python compatibility**: Match the reference Python implementation exactly, verified via KAT tests
2. **WASM export**: Browser signing for Starknet wallet/showcase
3. **Customizable hash**: Replace SHAKE256 with Poseidon for Starknet compatibility

## Scope

**In scope:**
- Falcon-512 only (n=512, q=12289)
- Sign and verify operations
- WASM bindings for browser
- Generic `HashToPoint` trait
- SHAKE256 implementation (for testing)
- Poseidon mock (real implementation deferred)

**Out of scope:**
- Cairo verifier (future work)
- Poseidon-to-Z_q mapping details (deferred)
- Other Falcon sizes (n=1024, etc.)

## Architecture

### Crate Structure

```
falcon-rs/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Public API
│   ├── falcon.rs           # Core Falcon-512 implementation
│   ├── hash_to_point.rs    # HashToPoint trait + SHAKE256 impl
│   ├── fft.rs              # FFT over R[x]/(x^n + 1)
│   ├── ntt.rs              # NTT over Z_q[x]/(x^n + 1)
│   ├── samplerz.rs         # Gaussian sampler over integers
│   ├── ffsampling.rs       # Fast Fourier sampling
│   ├── ntrugen.rs          # NTRU key generation
│   ├── encoding.rs         # Signature compression
│   ├── rng.rs              # ChaCha20-based PRNG
│   ├── constants.rs        # Precomputed FFT/NTT constants for n=512
│   └── wasm.rs             # WASM bindings (behind feature flag)
├── tests/
│   └── kat.rs              # KAT tests against Python vectors
└── test_vectors/
    └── *.json              # Converted from Python KATs
```

### HashToPoint Trait

Stateless generic trait for compile-time hash function selection:

```rust
pub trait HashToPoint {
    fn hash_to_point(message: &[u8], salt: &[u8; 40]) -> [i16; 512];
}

pub struct Shake256Hash;  // For testing against Python
pub struct PoseidonHash;  // For Starknet (mocked initially)

pub struct Falcon<H: HashToPoint> {
    _marker: PhantomData<H>,
}

impl<H: HashToPoint> Falcon<H> {
    pub fn sign(sk: &SecretKey, message: &[u8]) -> Signature;
    pub fn verify(vk: &VerifyingKey, message: &[u8], sig: &Signature) -> bool;
}
```

### Key and Signature Types

Constants:
- `N = 512`
- `Q = 12289`
- `SALT_LEN = 40`

```rust
pub struct SecretKey {
    f: [i16; N],
    g: [i16; N],
    capital_f: [i16; N],
    capital_g: [i16; N],
    tree: LdlTree,
}

impl SecretKey {
    pub fn to_bytes(&self) -> [u8; 3584];  // 4 polys × 896 bytes
    pub fn from_bytes(bytes: &[u8; 3584]) -> Result<Self, DecodeError>;
}

pub struct VerifyingKey {
    h: [i16; N],
}

impl VerifyingKey {
    pub fn to_bytes(&self) -> [u8; 896];   // 1 poly × 896 bytes
    pub fn from_bytes(bytes: &[u8; 896]) -> Result<Self, DecodeError>;
}

pub struct Signature {
    salt: [u8; SALT_LEN],
    s1: Vec<u8>,  // Compressed encoding
}
```

Serialization uses 14 bits per coefficient, matching Python's `serialize_poly`/`deserialize_to_poly`.

### WASM API

Only Poseidon variant exported to browser:

```rust
#[wasm_bindgen]
pub fn sign(secret_key: &[u8], message: &[u8]) -> Vec<u8>;

#[wasm_bindgen]
pub fn verify(verifying_key: &[u8], message: &[u8], signature: &[u8]) -> bool;

#[wasm_bindgen]
pub fn keygen() -> JsValue;  // Returns {sk: Uint8Array, vk: Uint8Array}
```

SHAKE256 is not compiled to WASM (only used for native testing).

### Dependencies

```toml
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

## Implementation Plan

### Phase 1: Math Primitives

1. **constants.rs** - FFT/NTT precomputed values for n=512
2. **ntt.rs** - Number Theoretic Transform (Z_q arithmetic)
3. **fft.rs** - Fast Fourier Transform (floating-point)

### Phase 2: Sampling

4. **rng.rs** - ChaCha20 PRNG
5. **samplerz.rs** - Gaussian sampler
   - Test checkpoint: `samplerz_KAT512`
6. **ffsampling.rs** - Fast Fourier sampling

### Phase 3: Core Falcon

7. **ntrugen.rs** - NTRU key generation (f, g, F, G)
8. **encoding.rs** - Signature compression/decompression
9. **hash_to_point.rs** - Trait + SHAKE256 impl
10. **falcon.rs** - Sign/verify
    - Test checkpoint: `sign_KAT`

### Phase 4: WASM

11. **wasm.rs** - Browser bindings with Poseidon mock
12. Integration test: Python keygen → Rust sign → Python verify

## Testing Strategy

- **KAT tests**: Convert Python test vectors to JSON, verify Rust produces identical output
- **Cross-language**: Generate keys in Python, sign in Rust, verify in Python (and vice versa)
- **Each phase**: Must pass relevant KATs before proceeding

## Future Work

- Implement real Poseidon hash with Starknet field mapping
- Cairo verifier contract
- Potential Falcon-1024 support
