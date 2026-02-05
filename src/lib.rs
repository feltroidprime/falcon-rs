//! Falcon-512 signature scheme implementation.

pub mod common;
pub mod constants;
pub mod encoding;
pub mod falcon;
pub mod ffsampling;
pub mod fft;
pub mod hash_to_point;
pub mod nist_compat;
pub mod nist_drbg;
pub mod ntrugen;
pub mod ntt;
pub mod rng;
pub mod samplerz;

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
