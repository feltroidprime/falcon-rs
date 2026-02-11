//! Poseidon XOF hash_to_point for Falcon-512 (Starknet-compatible).
//!
//! Uses lambdaworks PoseidonCairoStark252 to match the Cairo implementation.
//! Produces 512 coefficients in [0, Q) from (message, salt) using:
//! - Poseidon sponge (rate=2, capacity=1)
//! - Base-Q extraction: felt252 -> 2x u128 -> 6 DivRem-by-Q each -> 12 coefficients per felt252

use crate::{N, Q};
use lambdaworks_crypto::hash::poseidon::starknet::PoseidonCairoStark252;
use lambdaworks_crypto::hash::poseidon::Poseidon;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;

pub type Felt = FieldElement<Stark252PrimeField>;

pub struct PoseidonHashToPoint;

impl PoseidonHashToPoint {
    /// Hash message and salt (as felt252 arrays) to 512 Zq coefficients.
    /// This matches the Cairo PoseidonHashToPoint implementation exactly.
    pub fn hash_to_point(message: &[Felt], salt: &[Felt]) -> [i16; N] {
        let mut state = vec![Felt::zero(), Felt::zero(), Felt::zero()];

        // Absorb message then salt (rate=2)
        absorb(&mut state, message);
        absorb(&mut state, salt);
        state[2] = state[2] + Felt::one(); // domain separation

        // Squeeze
        let mut coeffs = [0i16; N];
        let mut idx = 0;
        while idx < N {
            PoseidonCairoStark252::hades_permutation(&mut state);
            idx += extract_12_from_felt(&state[0], &mut coeffs, idx);
            if idx >= N {
                break;
            }
            idx += extract_12_from_felt(&state[1], &mut coeffs, idx);
        }
        coeffs
    }
}

fn absorb(state: &mut Vec<Felt>, input: &[Felt]) {
    let mut iter = input.iter();
    loop {
        match iter.next() {
            None => break,
            Some(first) => {
                state[0] = state[0] + *first;
                match iter.next() {
                    Some(second) => state[1] = state[1] + *second,
                    None => state[1] = state[1] + Felt::one(), // pad
                }
                PoseidonCairoStark252::hades_permutation(state);
            }
        }
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
