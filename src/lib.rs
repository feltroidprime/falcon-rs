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
pub mod common;
pub mod nist_compat;

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
