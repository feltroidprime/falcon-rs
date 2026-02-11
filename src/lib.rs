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
pub mod poseidon_hash;
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
