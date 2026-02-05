# Falcon-RS

Rust implementation of Falcon-512 post-quantum signature scheme.

## Project Goal

Port the Python reference implementation (`falcon.py/`) to Rust with:
- WASM support for browser signing
- Generic `HashToPoint` trait to swap SHAKE256 for Poseidon
- 1:1 compatibility with Python verified via KAT tests

Target use case: Starknet browser wallet with post-quantum signatures.

## Current Status

**Planning complete.** Ready for implementation.

## Key Files

- `docs/plans/2026-02-05-falcon-rs-design.md` - Design decisions
- `docs/plans/2026-02-05-falcon-rs-implementation.md` - 15-task implementation plan
- `falcon.py/` - Python reference implementation (read-only, for reference)

## To Continue Implementation

```
Execute docs/plans/2026-02-05-falcon-rs-implementation.md task by task.
```

## Architecture Summary

- **Falcon-512 only** (n=512, q=12289)
- **Generic trait**: `Falcon<H: HashToPoint>` - hash function at compile time
- **WASM**: Only exports Poseidon variant (SHAKE256 for native testing only)
- **Serialization**: 14 bits per coefficient, matches Python format

## Test Strategy

- KAT tests from Python (`test_vectors/`)
- Cross-language: Python keygen → Rust verify (and vice versa)
