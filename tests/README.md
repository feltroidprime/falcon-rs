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

# Single test
cargo test --features shake test_sign_verify -- --nocapture
```

## Test Vectors

Test vectors are stored in `test_vectors/` as JSON files:

| File | Description | Source |
|------|-------------|--------|
| `nist_kat.json` | Official NIST known-answer tests | NIST PQC Round 3 |
| `samplerz_kat512_python.json` | Sampler validation data | Generated from falcon.py |
| `hash_to_point_kat.json` | Hash function test data | Generated from falcon.py |

## Test Categories

### Unit Tests
- `samplerz_kat.rs` - Validates discrete Gaussian sampler against reference

### Integration Tests
- `nist_kat_test.rs` - Verifies keygen and encoding match NIST vectors
- `nist_kat_sign_test.rs` - Full signing pipeline with sk parsing and pk reconstruction

### Cross-Language Tests
- `cross_language_test.rs` - Ensures Rust implementation matches Python reference

## Adding New Tests

1. Add test vectors to `test_vectors/` as JSON
2. Create test file in `tests/`
3. Use `include_str!` macro to load JSON at compile time
4. Run with `cargo test --features shake`
