//! Common utilities used across modules.

/// Split a polynomial f into even and odd coefficients.
/// f(x) -> (f0(x^2), f1(x^2)) where f(x) = f0(x^2) + x*f1(x^2)
pub fn split<T: Copy + Default, const N: usize, const HALF: usize>(f: &[T; N]) -> ([T; HALF], [T; HALF]) {
    let mut f0 = [T::default(); HALF];
    let mut f1 = [T::default(); HALF];
    for i in 0..HALF {
        f0[i] = f[2 * i];
        f1[i] = f[2 * i + 1];
    }
    (f0, f1)
}

/// Merge two polynomials into one.
/// (f0, f1) -> f where f(x) = f0(x^2) + x*f1(x^2)
pub fn merge<T: Copy + Default, const N: usize, const HALF: usize>(f0: &[T; HALF], f1: &[T; HALF]) -> [T; N] {
    let mut f = [T::default(); N];
    for i in 0..HALF {
        f[2 * i] = f0[i];
        f[2 * i + 1] = f1[i];
    }
    f
}

/// Compute the squared Euclidean norm of a vector of polynomials.
pub fn sqnorm(v: &[&[i32]]) -> i64 {
    let mut res = 0i64;
    for poly in v {
        for &coef in *poly {
            res += (coef as i64) * (coef as i64);
        }
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_merge_roundtrip() {
        let f: [i32; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let (f0, f1): ([i32; 4], [i32; 4]) = split(&f);
        assert_eq!(f0, [1, 3, 5, 7]);
        assert_eq!(f1, [2, 4, 6, 8]);
        let f_back: [i32; 8] = merge(&f0, &f1);
        assert_eq!(f, f_back);
    }

    #[test]
    fn test_sqnorm() {
        let a = [3, 4];
        let b = [0, 5];
        assert_eq!(sqnorm(&[&a[..], &b[..]]), 9 + 16 + 0 + 25);
    }
}
