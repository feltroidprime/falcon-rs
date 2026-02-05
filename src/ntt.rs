//! Number Theoretic Transform over Z_q[x]/(x^n + 1).

use crate::constants::{ntt_roots, INV_MOD_Q, I2, SQR1};
use crate::Q;

/// Split a polynomial in NTT representation.
pub fn split_ntt(f_ntt: &[i32]) -> (Vec<i32>, Vec<i32>) {
    let n = f_ntt.len();
    let w = ntt_roots(n);
    let mut f0_ntt = vec![0i32; n / 2];
    let mut f1_ntt = vec![0i32; n / 2];

    for i in 0..n / 2 {
        let sum = (f_ntt[2 * i] + f_ntt[2 * i + 1]).rem_euclid(Q);
        let diff = (f_ntt[2 * i] - f_ntt[2 * i + 1]).rem_euclid(Q);
        f0_ntt[i] = ((I2 as i64 * sum as i64) % Q as i64) as i32;
        f1_ntt[i] = ((I2 as i64 * diff as i64 * INV_MOD_Q[w[2 * i] as usize] as i64) % Q as i64) as i32;
    }
    (f0_ntt, f1_ntt)
}

/// Merge two polynomials in NTT representation.
pub fn merge_ntt(f0_ntt: &[i32], f1_ntt: &[i32]) -> Vec<i32> {
    let n = 2 * f0_ntt.len();
    let w = ntt_roots(n);
    let mut f_ntt = vec![0i32; n];

    for i in 0..n / 2 {
        let wf1 = ((w[2 * i] as i64 * f1_ntt[i] as i64) % Q as i64) as i32;
        f_ntt[2 * i] = (f0_ntt[i] + wf1).rem_euclid(Q);
        f_ntt[2 * i + 1] = (f0_ntt[i] - wf1).rem_euclid(Q);
    }
    f_ntt
}

/// Compute NTT of a polynomial (coefficient -> NTT representation).
pub fn ntt(f: &[i32]) -> Vec<i32> {
    let n = f.len();
    if n > 2 {
        let mut f0 = vec![0i32; n / 2];
        let mut f1 = vec![0i32; n / 2];
        for i in 0..n / 2 {
            f0[i] = f[2 * i];
            f1[i] = f[2 * i + 1];
        }
        let f0_ntt = ntt(&f0);
        let f1_ntt = ntt(&f1);
        merge_ntt(&f0_ntt, &f1_ntt)
    } else {
        let mut f_ntt = vec![0i32; n];
        f_ntt[0] = (f[0] + ((SQR1 as i64 * f[1] as i64) % Q as i64) as i32).rem_euclid(Q);
        f_ntt[1] = (f[0] - ((SQR1 as i64 * f[1] as i64) % Q as i64) as i32).rem_euclid(Q);
        f_ntt
    }
}

/// Compute inverse NTT (NTT -> coefficient representation).
pub fn intt(f_ntt: &[i32]) -> Vec<i32> {
    let n = f_ntt.len();
    if n > 2 {
        let (f0_ntt, f1_ntt) = split_ntt(f_ntt);
        let f0 = intt(&f0_ntt);
        let f1 = intt(&f1_ntt);
        // merge
        let mut f = vec![0i32; n];
        for i in 0..n / 2 {
            f[2 * i] = f0[i];
            f[2 * i + 1] = f1[i];
        }
        f
    } else {
        let mut f = vec![0i32; n];
        let sum = (f_ntt[0] + f_ntt[1]).rem_euclid(Q);
        let diff = (f_ntt[0] - f_ntt[1]).rem_euclid(Q);
        f[0] = ((I2 as i64 * sum as i64) % Q as i64) as i32;
        f[1] = ((I2 as i64 * INV_MOD_Q[SQR1 as usize] as i64 * diff as i64) % Q as i64) as i32;
        f
    }
}

/// Addition of two polynomials in Z_q.
pub fn add_zq(f: &[i32], g: &[i32]) -> Vec<i32> {
    assert_eq!(f.len(), g.len());
    f.iter().zip(g.iter()).map(|(&a, &b)| (a + b).rem_euclid(Q)).collect()
}

/// Negation of a polynomial in Z_q.
pub fn neg_zq(f: &[i32]) -> Vec<i32> {
    f.iter().map(|&a| (-a).rem_euclid(Q)).collect()
}

/// Subtraction of two polynomials in Z_q.
pub fn sub_zq(f: &[i32], g: &[i32]) -> Vec<i32> {
    add_zq(f, &neg_zq(g))
}

/// Multiplication in NTT representation (pointwise).
pub fn mul_ntt(f_ntt: &[i32], g_ntt: &[i32]) -> Vec<i32> {
    assert_eq!(f_ntt.len(), g_ntt.len());
    f_ntt.iter().zip(g_ntt.iter())
        .map(|(&a, &b)| ((a as i64 * b as i64) % Q as i64) as i32)
        .collect()
}

/// Division in NTT representation (pointwise).
pub fn div_ntt(f_ntt: &[i32], g_ntt: &[i32]) -> Option<Vec<i32>> {
    assert_eq!(f_ntt.len(), g_ntt.len());
    if g_ntt.iter().any(|&x| x == 0) {
        return None;
    }
    Some(f_ntt.iter().zip(g_ntt.iter())
        .map(|(&a, &b)| ((a as i64 * INV_MOD_Q[b as usize] as i64) % Q as i64) as i32)
        .collect())
}

/// Multiplication of two polynomials in coefficient representation.
pub fn mul_zq(f: &[i32], g: &[i32]) -> Vec<i32> {
    intt(&mul_ntt(&ntt(f), &ntt(g)))
}

/// Division of two polynomials in coefficient representation.
pub fn div_zq(f: &[i32], g: &[i32]) -> Option<Vec<i32>> {
    div_ntt(&ntt(f), &ntt(g)).map(|r| intt(&r))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_intt_roundtrip() {
        let f = vec![1, 2, 3, 4];
        let f_ntt = ntt(&f);
        let f_back = intt(&f_ntt);
        assert_eq!(f, f_back);
    }

    #[test]
    fn test_ntt_intt_roundtrip_512() {
        let mut f = vec![0i32; 512];
        for i in 0..512 {
            f[i] = (i as i32 * 7 + 3) % Q;
        }
        let f_ntt = ntt(&f);
        let f_back = intt(&f_ntt);
        assert_eq!(f, f_back);
    }

    #[test]
    fn test_mul_zq() {
        // Multiply (1 + x) * (1 + x) = 1 + 2x + x^2
        // In ring Z_q[x]/(x^4 + 1): x^2 stays as x^2
        let f = vec![1, 1, 0, 0];
        let result = mul_zq(&f, &f);
        assert_eq!(result[0], 1);
        assert_eq!(result[1], 2);
        assert_eq!(result[2], 1);
        assert_eq!(result[3], 0);
    }

    #[test]
    fn test_mul_zq_wrap() {
        // Multiply (1 + x^3) * (1 + x^3) = 1 + 2x^3 + x^6
        // In Z_q[x]/(x^4 + 1): x^6 = x^2 * x^4 = -x^2
        // So result is 1 - x^2 + 2x^3 = [1, 0, q-1, 2]
        let f = vec![1, 0, 0, 1];
        let result = mul_zq(&f, &f);
        assert_eq!(result[0], 1);
        assert_eq!(result[1], 0);
        assert_eq!(result[2], Q - 1); // -1 mod q
        assert_eq!(result[3], 2);
    }

    #[test]
    fn test_div_zq() {
        let f = vec![1, 2, 3, 4];
        let g = vec![5, 6, 7, 8];
        let fg = mul_zq(&f, &g);
        let f_back = div_zq(&fg, &g).unwrap();
        assert_eq!(f, f_back);
    }
}
