//! Base-Q polynomial packing for Falcon public keys.
//!
//! Packs 512 Zq values into 29 felt252 slots using base Q=12289 encoding:
//!   felt252 = horner_pack(v0..v8) + horner_pack(v9..v17) * 2^128
//!
//! Matches the Cairo packing.cairo implementation exactly.

use crate::poseidon_hash::Felt;
use crate::Q;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;

const VALS_PER_U128: usize = 9;
const VALS_PER_FELT: usize = 18;
pub const PACKED_SLOTS: usize = 29;

/// Convert a u128 to Felt
fn felt_from_u128(v: u128) -> Felt {
    Felt::from(&UnsignedInteger::from_u128(v))
}

/// 2^128 as Felt
fn two_pow_128() -> Felt {
    Felt::from_hex("0x100000000000000000000000000000000").unwrap()
}

/// Pack 512 Zq values into 29 Felt values using base-Q Horner encoding.
pub fn pack_public_key(h_ntt: &[u16]) -> Vec<Felt> {
    assert_eq!(h_ntt.len(), 512);
    h_ntt
        .chunks(VALS_PER_FELT)
        .map(|chunk| {
            let split = chunk.len().min(VALS_PER_U128);
            let lo = horner_pack(&chunk[..split]);
            let hi = if chunk.len() > split {
                horner_pack(&chunk[split..])
            } else {
                0u128
            };
            felt_from_u128(lo) + felt_from_u128(hi) * two_pow_128()
        })
        .collect()
}

/// Unpack 29 Felt values back to 512 Zq values.
pub fn unpack_public_key(packed: &[Felt]) -> Vec<u16> {
    let mut result = Vec::with_capacity(512);
    let mut remaining = 512usize;

    for felt in packed {
        let bytes = felt.to_bytes_be();
        let high = u128::from_be_bytes(bytes[0..16].try_into().unwrap());
        let low = u128::from_be_bytes(bytes[16..32].try_into().unwrap());

        let lo_count = remaining.min(VALS_PER_U128);
        base_q_extract(low, lo_count, &mut result);
        remaining -= lo_count;

        if remaining > 0 {
            let hi_count = remaining.min(VALS_PER_U128);
            base_q_extract(high, hi_count, &mut result);
            remaining -= hi_count;
        }
    }
    result
}

fn horner_pack(values: &[u16]) -> u128 {
    let mut acc: u128 = 0;
    for &v in values.iter().rev() {
        acc = acc * Q as u128 + v as u128;
    }
    acc
}

fn base_q_extract(mut value: u128, count: usize, out: &mut Vec<u16>) {
    for _ in 0..count {
        out.push((value % Q as u128) as u16);
        value /= Q as u128;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packing_roundtrip() {
        let mut values = vec![0u16; 512];
        for i in 0..512 {
            values[i] = (i * 37 % 12289) as u16;
        }
        let packed = pack_public_key(&values);
        assert_eq!(packed.len(), PACKED_SLOTS);
        let unpacked = unpack_public_key(&packed);
        assert_eq!(unpacked, values);
    }

    #[test]
    fn test_packing_edge_cases() {
        // All zeros
        let zeros = vec![0u16; 512];
        assert_eq!(unpack_public_key(&pack_public_key(&zeros)), zeros);

        // All max
        let maxes = vec![12288u16; 512];
        assert_eq!(unpack_public_key(&pack_public_key(&maxes)), maxes);
    }
}

#[cfg(test)]
mod hex_tests {
    use super::*;
    use crate::poseidon_hash::Felt;
    use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
    use num_bigint::BigUint;

    #[test]
    fn test_to_hex_vs_to_bytes_be() {
        // Test with a known value
        let lo: u128 = 12345;
        let hi: u128 = 67890;

        let felt = Felt::from(&UnsignedInteger::from_u128(lo))
            + Felt::from(&UnsignedInteger::from_u128(hi))
                * Felt::from_hex("0x100000000000000000000000000000000").unwrap();

        let hex_str = felt.to_hex();
        let bytes = felt.to_bytes_be();
        let bytes_num = BigUint::from_bytes_be(&bytes);
        let bytes_hex = format!("{:064x}", bytes_num);

        println!("to_hex():      {}", hex_str);
        println!("to_bytes_be(): {}", bytes_hex);
        println!("Match: {}", hex_str == bytes_hex);

        // Also check a simple value
        let one = Felt::from(1u64);
        println!("\nFelt(1).to_hex() = {}", one.to_hex());
        let one_bytes = one.to_bytes_be();
        let one_bytes_num = BigUint::from_bytes_be(&one_bytes);
        println!("Felt(1) bytes = {}", one_bytes_num);

        // Parse to_hex back
        let hex_num = BigUint::parse_bytes(hex_str.as_bytes(), 16).unwrap();
        println!("\nto_hex as decimal:      {}", hex_num);

        let bytes_dec = BigUint::from_bytes_be(&bytes);
        println!("to_bytes_be as decimal: {}", bytes_dec);

        assert_eq!(hex_num, bytes_dec, "to_hex and to_bytes_be should match");
    }

    #[test]
    fn test_packing_hex_values() {
        // Pack known values and check the hex
        let mut values = vec![0u16; 512];
        for i in 0..512 {
            values[i] = (i * 37 % 12289) as u16;
        }
        let packed = pack_public_key(&values);

        // Check first packed felt252
        let f = &packed[0];
        let bytes = f.to_bytes_be();
        let canonical = BigUint::from_bytes_be(&bytes);
        let hex_str = f.to_hex();
        let from_hex = BigUint::parse_bytes(hex_str.as_bytes(), 16).unwrap();

        println!("Packed[0] canonical (bytes): {}", canonical);
        println!("Packed[0] from to_hex():     {}", from_hex);
        println!("Match: {}", canonical == from_hex);

        // Split into u128 halves
        let two_128 = BigUint::from(1u64) << 128;
        let mask = &two_128 - BigUint::from(1u64);
        let low = &canonical & &mask;
        let high = &canonical >> 128;
        let q9 = BigUint::from(12289u64).pow(9);

        println!("\nlow = {}, < Q^9: {}", low, low < q9);
        println!("high = {}, < Q^9: {}", high, high < q9);
    }
}
