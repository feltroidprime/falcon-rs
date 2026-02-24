//! Hint generation for Falcon verification.
//!
//! Generates the mul_hint = INTT(NTT(s1) * pk_h_ntt) that allows
//! Cairo to verify NTT products without computing INTT on-chain.

use crate::ntt::{intt, mul_ntt, ntt};
use crate::Q;

/// Generate INTT(NTT(s1) * pk_h_ntt) — the mul_hint for verification.
pub fn generate_mul_hint(s1: &[u16], pk_h_ntt: &[u16]) -> Vec<u16> {
    let s1_i32: Vec<i32> = s1.iter().map(|&v| v as i32).collect();
    let pk_i32: Vec<i32> = pk_h_ntt.iter().map(|&v| v as i32).collect();

    let s1_ntt = ntt(&s1_i32);
    let product_ntt = mul_ntt(&s1_ntt, &pk_i32);
    let product = intt(&product_ntt);

    product.iter().map(|&v| v.rem_euclid(Q) as u16).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hint_generation() {
        // s1 = [1, 0, 0, ...], pk_ntt = NTT([1, 0, 0, ...])
        let mut s1 = vec![0u16; 512];
        s1[0] = 1;
        let pk_coeff: Vec<i32> = s1.iter().map(|&v| v as i32).collect();
        let pk_ntt = ntt(&pk_coeff);
        let pk_u16: Vec<u16> = pk_ntt.iter().map(|&v| v.rem_euclid(Q) as u16).collect();

        let hint = generate_mul_hint(&s1, &pk_u16);
        assert_eq!(hint.len(), 512);
        // hint = INTT(NTT([1,0...]) * NTT([1,0...])) = [1,0...]
        assert_eq!(hint[0], 1);
        for i in 1..512 {
            assert_eq!(hint[i], 0, "expected 0 at index {i}, got {}", hint[i]);
        }
    }
}
