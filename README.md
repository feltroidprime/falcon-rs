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

## Security Considerations

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

## References

- [Falcon Specification](https://falcon-sign.info/)
- [NIST PQC Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Falcon Round 3 Submission](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions)

## License

MIT License - see [LICENSE](LICENSE) for details.
