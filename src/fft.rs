//! Fast Fourier Transform over R[x]/(x^n + 1).

use crate::constants::fft_roots;

/// Complex number with f64 components.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Complex {
    pub re: f64,
    pub im: f64,
}

impl Complex {
    pub const ZERO: Complex = Complex { re: 0.0, im: 0.0 };
    pub const ONE: Complex = Complex { re: 1.0, im: 0.0 };
    pub const I: Complex = Complex { re: 0.0, im: 1.0 };

    #[inline]
    pub fn new(re: f64, im: f64) -> Self {
        Complex { re, im }
    }

    #[inline]
    pub fn conj(self) -> Self {
        Complex { re: self.re, im: -self.im }
    }
}

impl Default for Complex {
    fn default() -> Self {
        Complex::ZERO
    }
}

impl std::ops::Add for Complex {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Complex { re: self.re + rhs.re, im: self.im + rhs.im }
    }
}

impl std::ops::Sub for Complex {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Complex { re: self.re - rhs.re, im: self.im - rhs.im }
    }
}

impl std::ops::Mul for Complex {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Complex {
            re: self.re * rhs.re - self.im * rhs.im,
            im: self.re * rhs.im + self.im * rhs.re,
        }
    }
}

impl std::ops::Div for Complex {
    type Output = Self;
    #[inline]
    fn div(self, rhs: Self) -> Self {
        let denom = rhs.re * rhs.re + rhs.im * rhs.im;
        Complex {
            re: (self.re * rhs.re + self.im * rhs.im) / denom,
            im: (self.im * rhs.re - self.re * rhs.im) / denom,
        }
    }
}

impl std::ops::Mul<f64> for Complex {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: f64) -> Self {
        Complex { re: self.re * rhs, im: self.im * rhs }
    }
}

impl std::ops::Neg for Complex {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        Complex { re: -self.re, im: -self.im }
    }
}

/// Get FFT root at index i for degree n.
#[inline]
fn fft_root(n: usize, i: usize) -> Complex {
    let (re, im) = fft_roots(n)[i];
    Complex::new(re, im)
}

/// Split a polynomial in FFT representation.
pub fn split_fft(f_fft: &[Complex]) -> (Vec<Complex>, Vec<Complex>) {
    let n = f_fft.len();
    let mut f0_fft = vec![Complex::ZERO; n / 2];
    let mut f1_fft = vec![Complex::ZERO; n / 2];

    for i in 0..n / 2 {
        f0_fft[i] = (f_fft[2 * i] + f_fft[2 * i + 1]) * 0.5;
        f1_fft[i] = (f_fft[2 * i] - f_fft[2 * i + 1]) * 0.5 * fft_root(n, 2 * i).conj();
    }
    (f0_fft, f1_fft)
}

/// Merge two polynomials in FFT representation.
pub fn merge_fft(f0_fft: &[Complex], f1_fft: &[Complex]) -> Vec<Complex> {
    let n = 2 * f0_fft.len();
    let mut f_fft = vec![Complex::ZERO; n];

    for i in 0..n / 2 {
        let w = fft_root(n, 2 * i);
        let wf1 = w * f1_fft[i];
        f_fft[2 * i] = f0_fft[i] + wf1;
        f_fft[2 * i + 1] = f0_fft[i] - wf1;
    }
    f_fft
}

/// Compute FFT of a polynomial (coefficient -> FFT representation).
pub fn fft(f: &[f64]) -> Vec<Complex> {
    let n = f.len();
    if n > 2 {
        let mut f0 = vec![0.0f64; n / 2];
        let mut f1 = vec![0.0f64; n / 2];
        for i in 0..n / 2 {
            f0[i] = f[2 * i];
            f1[i] = f[2 * i + 1];
        }
        let f0_fft = fft(&f0);
        let f1_fft = fft(&f1);
        merge_fft(&f0_fft, &f1_fft)
    } else {
        let mut f_fft = vec![Complex::ZERO; n];
        f_fft[0] = Complex::new(f[0], f[1]);
        f_fft[1] = Complex::new(f[0], -f[1]);
        f_fft
    }
}

/// Compute inverse FFT (FFT -> coefficient representation).
pub fn ifft(f_fft: &[Complex]) -> Vec<f64> {
    let n = f_fft.len();
    if n > 2 {
        let (f0_fft, f1_fft) = split_fft(f_fft);
        let f0 = ifft(&f0_fft);
        let f1 = ifft(&f1_fft);
        let mut f = vec![0.0f64; n];
        for i in 0..n / 2 {
            f[2 * i] = f0[i];
            f[2 * i + 1] = f1[i];
        }
        f
    } else {
        let mut f = vec![0.0f64; n];
        f[0] = f_fft[0].re;
        f[1] = f_fft[0].im;
        f
    }
}

// FFT-representation operations

/// Addition of two polynomials (FFT representation).
pub fn add_fft(f: &[Complex], g: &[Complex]) -> Vec<Complex> {
    f.iter().zip(g.iter()).map(|(&a, &b)| a + b).collect()
}

/// Subtraction of two polynomials (FFT representation).
pub fn sub_fft(f: &[Complex], g: &[Complex]) -> Vec<Complex> {
    f.iter().zip(g.iter()).map(|(&a, &b)| a - b).collect()
}

/// Multiplication of two polynomials (FFT representation, pointwise).
pub fn mul_fft(f: &[Complex], g: &[Complex]) -> Vec<Complex> {
    f.iter().zip(g.iter()).map(|(&a, &b)| a * b).collect()
}

/// Division of two polynomials (FFT representation, pointwise).
pub fn div_fft(f: &[Complex], g: &[Complex]) -> Vec<Complex> {
    f.iter().zip(g.iter()).map(|(&a, &b)| a / b).collect()
}

/// Adjoint of a polynomial (FFT representation).
pub fn adj_fft(f: &[Complex]) -> Vec<Complex> {
    f.iter().map(|&a| a.conj()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fft_ifft_roundtrip() {
        let f = vec![1.0, 2.0, 3.0, 4.0];
        let f_fft = fft(&f);
        let f_back = ifft(&f_fft);
        for i in 0..4 {
            assert!((f[i] - f_back[i]).abs() < 1e-10);
        }
    }

    #[test]
    fn test_fft_ifft_roundtrip_512() {
        let mut f = vec![0.0f64; 512];
        for i in 0..512 {
            f[i] = (i as f64 * 0.7 + 0.3).sin();
        }
        let f_fft = fft(&f);
        let f_back = ifft(&f_fft);
        for i in 0..512 {
            assert!((f[i] - f_back[i]).abs() < 1e-10, "Mismatch at index {}: {} vs {}", i, f[i], f_back[i]);
        }
    }

    #[test]
    fn test_complex_ops() {
        let a = Complex::new(1.0, 2.0);
        let b = Complex::new(3.0, 4.0);
        let sum = a + b;
        assert_eq!(sum.re, 4.0);
        assert_eq!(sum.im, 6.0);

        let diff = a - b;
        assert_eq!(diff.re, -2.0);
        assert_eq!(diff.im, -2.0);

        // (1+2i) * (3+4i) = 3 + 4i + 6i + 8i^2 = 3 + 10i - 8 = -5 + 10i
        let prod = a * b;
        assert_eq!(prod.re, -5.0);
        assert_eq!(prod.im, 10.0);
    }

    #[test]
    fn test_mul_via_fft() {
        // Multiply (1 + x) * (1 + x) = 1 + 2x + x^2
        let f = vec![1.0, 1.0, 0.0, 0.0];
        let f_fft = fft(&f);
        let result_fft = mul_fft(&f_fft, &f_fft);
        let result = ifft(&result_fft);
        assert!((result[0] - 1.0).abs() < 1e-10);
        assert!((result[1] - 2.0).abs() < 1e-10);
        assert!((result[2] - 1.0).abs() < 1e-10);
        assert!((result[3] - 0.0).abs() < 1e-10);
    }
}
