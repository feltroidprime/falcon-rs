//! Poseidon hash_to_point for Falcon-512 (Starknet-compatible).
//!
//! Uses lambdaworks PoseidonCairoStark252 to match the Cairo implementation.
//! Produces 512 coefficients in [0, Q) from (message, salt) using:
//! - poseidon_hash_span(message || salt) -> single felt252 seed
//! - Squeeze: 22 hades_permutations, base-Q extraction (12 Zq per felt252)

use crate::hash_to_point::HashToPoint;
use crate::{N, Q};
use lambdaworks_crypto::hash::poseidon::starknet::PoseidonCairoStark252;
use lambdaworks_crypto::hash::poseidon::Poseidon;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;

pub type Felt = FieldElement<Stark252PrimeField>;

pub struct PoseidonHashToPoint;

impl HashToPoint for PoseidonHashToPoint {
    type Input = Felt;

    /// Hash message and salt (as felt252 arrays) to 512 Zq coefficients.
    /// This matches the Cairo PoseidonHashToPoint implementation exactly.
    fn hash_to_point(message: &[Felt], salt: &[Felt]) -> [i16; N] {
        // Absorb: poseidon_hash_span(message || salt) -> single felt252 seed
        let combined: Vec<Felt> = message.iter().chain(salt.iter()).cloned().collect();
        let seed = PoseidonCairoStark252::hash_many(&combined);

        // Squeeze: 21 full rounds (504 coefficients) + 1 partial round (8 coefficients)
        let mut state = [seed, Felt::zero(), Felt::zero()];
        let mut coeffs = [0i16; N];
        let mut idx = 0;

        for _ in 0..21 {
            PoseidonCairoStark252::hades_permutation(&mut state);
            idx += extract_12_from_felt(&state[0], &mut coeffs, idx);
            idx += extract_12_from_felt(&state[1], &mut coeffs, idx);
        }

        // Final round: only need 8 more from state[0]
        PoseidonCairoStark252::hades_permutation(&mut state);
        extract_12_from_felt(&state[0], &mut coeffs, idx);
        // extract_12 stops at N=512, giving exactly 8 (6 from low + 2 from high)

        coeffs
    }
}

fn extract_12_from_felt(value: &Felt, out: &mut [i16; N], start: usize) -> usize {
    let bytes = value.to_bytes_be();
    // bytes is 32 bytes big-endian: [0..16] = high u128, [16..32] = low u128
    let high = u128::from_be_bytes(bytes[0..16].try_into().unwrap());
    let low = u128::from_be_bytes(bytes[16..32].try_into().unwrap());

    let mut count = 0;
    // Extract 6 from low u128 first (matching Cairo's extract_6_from_low)
    count += extract_6_from_u128(low, out, start + count);
    // Extract 6 from high (matching Cairo's extract_6_from_high)
    count += extract_6_from_u128(high, out, start + count);
    count
}

fn extract_6_from_u128(mut value: u128, out: &mut [i16; N], start: usize) -> usize {
    for i in 0..6 {
        if start + i >= N {
            return i;
        }
        out[start + i] = (value % Q as u128) as i16;
        value /= Q as u128;
    }
    6
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_hash_deterministic() {
        let msg = [Felt::from(42u64)];
        let salt = [Felt::from(1u64), Felt::from(2u64)];
        let r1 = PoseidonHashToPoint::hash_to_point(&msg, &salt);
        let r2 = PoseidonHashToPoint::hash_to_point(&msg, &salt);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_poseidon_hash_range() {
        let msg = [Felt::from(42u64)];
        let salt = [Felt::from(1u64), Felt::from(2u64)];
        let result = PoseidonHashToPoint::hash_to_point(&msg, &salt);
        for &v in &result {
            assert!(v >= 0 && (v as i32) < Q, "out of range: {v}");
        }
    }

    #[test]
    fn test_poseidon_hash_different_inputs() {
        let msg1 = [Felt::from(1u64)];
        let msg2 = [Felt::from(2u64)];
        let salt = [Felt::from(0u64), Felt::from(0u64)];
        let r1 = PoseidonHashToPoint::hash_to_point(&msg1, &salt);
        let r2 = PoseidonHashToPoint::hash_to_point(&msg2, &salt);
        assert_ne!(r1, r2);
    }
}
