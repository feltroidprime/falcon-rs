//! Signature compression and public key serialization.

use crate::{N, Q};

/// Number of bits per coefficient for public key serialization.
const BITS_PER_COEF: usize = 14;

/// Compress a polynomial to bytes using sign + low 7 bits + unary high bits encoding.
///
/// Returns None if the encoding exceeds `slen` bytes.
pub fn compress(v: &[i32], slen: usize) -> Option<Vec<u8>> {
    let mut bits = Vec::with_capacity(8 * slen);

    for &coef in v {
        // Sign bit
        bits.push(coef < 0);

        // Low 7 bits (binary)
        let abs_coef = coef.unsigned_abs();
        for i in (0..7).rev() {
            bits.push((abs_coef >> i) & 1 == 1);
        }

        // High bits (unary: zeros followed by one)
        let high = abs_coef >> 7;
        for _ in 0..high {
            bits.push(false);
        }
        bits.push(true);
    }

    if bits.len() > 8 * slen {
        return None;
    }

    // Pad to slen bytes
    bits.resize(8 * slen, false);

    // Convert to bytes
    let bytes: Vec<u8> = (0..slen)
        .map(|i| {
            let mut byte = 0u8;
            for j in 0..8 {
                if bits[8 * i + j] {
                    byte |= 1 << (7 - j);
                }
            }
            byte
        })
        .collect();

    Some(bytes)
}

/// Decompress bytes to polynomial.
///
/// Returns None if the encoding is invalid.
pub fn decompress(x: &[u8], n: usize) -> Option<Vec<i32>> {
    // Convert bytes to bits
    let mut bits: Vec<bool> = Vec::with_capacity(8 * x.len());
    for &byte in x {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }

    // Remove trailing zeros
    while bits.last() == Some(&false) {
        bits.pop();
    }

    let mut v = Vec::with_capacity(n);
    let mut pos = 0;

    while pos < bits.len() && v.len() < n {
        // Check bounds
        if pos + 8 > bits.len() {
            return None;
        }

        // Sign
        let sign = if bits[pos] { -1 } else { 1 };
        pos += 1;

        // Low 7 bits
        let mut low = 0i32;
        for i in 0..7 {
            if bits[pos + i] {
                low |= 1 << (6 - i);
            }
        }
        pos += 7;

        // High bits (unary)
        let mut high = 0i32;
        while pos < bits.len() && !bits[pos] {
            high += 1;
            pos += 1;
        }

        // Skip the terminating '1'
        if pos >= bits.len() {
            return None;
        }
        pos += 1;

        let coef = sign * (low + (high << 7));

        // Reject -0 (ensures unique encoding)
        if coef == 0 && sign == -1 {
            return None;
        }

        v.push(coef);
    }

    if v.len() != n {
        return None;
    }

    Some(v)
}

/// Serialize a public key polynomial to bytes.
///
/// Each coefficient is stored using 14 bits.
/// Coefficients must be in range [0, Q).
pub fn serialize_public_key(poly: &[i32; N]) -> Vec<u8> {
    // Pack 14-bit values into bytes
    let bytelen = (N * BITS_PER_COEF + 7) / 8;
    let mut bytes = vec![0u8; bytelen];

    let mut bit_pos = 0;
    for &coef in poly {
        // Ensure coefficient is in valid range
        let coef = coef.rem_euclid(Q) as u32;

        // Write 14 bits
        for i in 0..BITS_PER_COEF {
            if (coef >> i) & 1 == 1 {
                let byte_idx = bit_pos / 8;
                let bit_idx = bit_pos % 8;
                bytes[byte_idx] |= 1 << bit_idx;
            }
            bit_pos += 1;
        }
    }

    bytes
}

/// Deserialize a public key polynomial from bytes.
///
/// Returns None if the encoding is invalid.
pub fn deserialize_public_key(bytes: &[u8]) -> Option<[i32; N]> {
    let expected_len = (N * BITS_PER_COEF + 7) / 8;
    if bytes.len() != expected_len {
        return None;
    }

    let mut poly = [0i32; N];

    let mut bit_pos = 0;
    for i in 0..N {
        let mut coef = 0u32;
        for j in 0..BITS_PER_COEF {
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if (bytes[byte_idx] >> bit_idx) & 1 == 1 {
                coef |= 1 << j;
            }
            bit_pos += 1;
        }

        // Validate coefficient
        if coef >= Q as u32 {
            return None;
        }
        poly[i] = coef as i32;
    }

    Some(poly)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_roundtrip() {
        let v = vec![1, -2, 3, -4, 0, 127, -128, 255];
        let compressed = compress(&v, 100).unwrap();
        let decompressed = decompress(&compressed, v.len()).unwrap();
        assert_eq!(v, decompressed);
    }

    #[test]
    fn test_compress_decompress_zeros() {
        let v = vec![0, 0, 0, 0];
        let compressed = compress(&v, 100).unwrap();
        let decompressed = decompress(&compressed, v.len()).unwrap();
        assert_eq!(v, decompressed);
    }

    #[test]
    fn test_compress_decompress_large_values() {
        let v = vec![256, -256, 512, -512, 1000, -1000];
        let compressed = compress(&v, 100).unwrap();
        let decompressed = decompress(&compressed, v.len()).unwrap();
        assert_eq!(v, decompressed);
    }

    #[test]
    fn test_compress_too_long() {
        let v = vec![10000; 100]; // Large values need many bits
        let result = compress(&v, 10); // Too small
        assert!(result.is_none());
    }

    #[test]
    fn test_serialize_deserialize_public_key() {
        let mut poly = [0i32; N];
        for i in 0..N {
            poly[i] = (i as i32 * 17) % Q;
        }

        let bytes = serialize_public_key(&poly);
        let deserialized = deserialize_public_key(&bytes).unwrap();
        assert_eq!(poly, deserialized);
    }

    #[test]
    fn test_public_key_length() {
        let poly = [0i32; N];
        let bytes = serialize_public_key(&poly);
        // 512 coefficients * 14 bits = 7168 bits = 896 bytes
        assert_eq!(bytes.len(), 896);
    }
}
