//! Hash-to-point trait for customizable hash functions.
//!
//! Falcon requires hashing messages to points in Z_q[X]/(X^n + 1).
//! This module provides the trait and a default SHAKE256 implementation.

use crate::{N, Q};

/// Trait for hashing message to polynomial in Z_q[x]/(x^n + 1).
///
/// This trait allows swapping the hash function used in Falcon,
/// enabling use of Poseidon for Starknet compatibility.
///
/// The associated type `Input` determines the element type for message and salt:
/// - `u8` for byte-oriented hashing (SHAKE256)
/// - `Felt` for field-element hashing (Poseidon/Starknet)
pub trait HashToPoint {
    /// Element type for message and salt slices.
    type Input;

    /// Hash a message with salt to a polynomial in Z_q[x].
    fn hash_to_point(message: &[Self::Input], salt: &[Self::Input]) -> [i16; N];
}

/// SHAKE256-based hash (matches Python reference implementation).
#[cfg(feature = "shake")]
pub struct Shake256Hash;

#[cfg(feature = "shake")]
impl HashToPoint for Shake256Hash {
    type Input = u8;

    fn hash_to_point(message: &[u8], salt: &[u8]) -> [i16; N] {
        use sha3::{
            digest::{ExtendableOutput, Update, XofReader},
            Shake256,
        };

        let mut hasher = Shake256::default();
        hasher.update(salt);
        hasher.update(message);
        let mut reader = hasher.finalize_xof();

        // Rejection sampling parameter: k = floor(2^16 / q)
        let k = (1u32 << 16) / (Q as u32);
        let mut hashed = [0i16; N];
        let mut i = 0;

        while i < N {
            let mut buf = [0u8; 2];
            reader.read(&mut buf);
            // Big-endian as per Python reference
            let elt = ((buf[0] as u32) << 8) | (buf[1] as u32);

            // Rejection sampling to ensure uniform distribution
            if elt < k * (Q as u32) {
                hashed[i] = (elt % (Q as u32)) as i16;
                i += 1;
            }
        }

        hashed
    }
}

#[cfg(all(test, feature = "shake"))]
mod tests {
    use super::*;
    use crate::SALT_LEN;

    #[test]
    fn test_shake256_hash_deterministic() {
        let message = b"Hello, Falcon!";
        let salt = [0u8; SALT_LEN];

        let hash1 = Shake256Hash::hash_to_point(message, &salt);
        let hash2 = Shake256Hash::hash_to_point(message, &salt);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_shake256_hash_different_messages() {
        let salt = [0u8; SALT_LEN];

        let hash1 = Shake256Hash::hash_to_point(b"message1", &salt);
        let hash2 = Shake256Hash::hash_to_point(b"message2", &salt);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_shake256_hash_different_salts() {
        let message = b"Hello, Falcon!";
        let salt1 = [0u8; SALT_LEN];
        let mut salt2 = [0u8; SALT_LEN];
        salt2[0] = 1;

        let hash1 = Shake256Hash::hash_to_point(message, &salt1);
        let hash2 = Shake256Hash::hash_to_point(message, &salt2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_shake256_hash_range() {
        let message = b"test message";
        let salt = [42u8; SALT_LEN];

        let hash = Shake256Hash::hash_to_point(message, &salt);

        // All coefficients should be in [0, Q)
        for &coef in &hash {
            assert!(coef >= 0);
            assert!((coef as i32) < Q);
        }
    }
}
