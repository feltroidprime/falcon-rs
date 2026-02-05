//! NTRU key generation for Falcon.

use crate::common::sqnorm;
use crate::fft::{add, adj, adj_fft, add_fft, div, div_fft, fft, ifft, mul, mul_fft};
use crate::ntt::ntt;
use crate::samplerz::samplerz;
use crate::{Q, N};
use num_bigint::BigInt;
use num_traits::{Zero, One, ToPrimitive, Signed};

/// Karatsuba multiplication between polynomials using BigInt.
/// Returns a polynomial of degree 2n-1 (length 2n).
fn karatsuba_big(a: &[BigInt], b: &[BigInt]) -> Vec<BigInt> {
    let n = a.len();
    if n == 1 {
        return vec![&a[0] * &b[0], BigInt::zero()];
    }

    let n2 = n / 2;
    let (a0, a1) = a.split_at(n2);
    let (b0, b1) = b.split_at(n2);

    let ax: Vec<BigInt> = a0.iter().zip(a1).map(|(x, y)| x + y).collect();
    let bx: Vec<BigInt> = b0.iter().zip(b1).map(|(x, y)| x + y).collect();

    let a0b0 = karatsuba_big(a0, b0);
    let a1b1 = karatsuba_big(a1, b1);
    let mut axbx = karatsuba_big(&ax, &bx);

    for i in 0..n {
        axbx[i] = &axbx[i] - &a0b0[i] - &a1b1[i];
    }

    let mut ab: Vec<BigInt> = (0..2*n).map(|_| BigInt::zero()).collect();
    for i in 0..n {
        ab[i] = &ab[i] + &a0b0[i];
        ab[i + n] = &ab[i + n] + &a1b1[i];
        ab[i + n2] = &ab[i + n2] + &axbx[i];
    }
    ab
}

/// Karatsuba multiplication mod (x^n + 1) using BigInt.
fn karamul_big(a: &[BigInt], b: &[BigInt]) -> Vec<BigInt> {
    let n = a.len();
    let ab = karatsuba_big(a, b);
    (0..n).map(|i| &ab[i] - &ab[i + n]).collect()
}

/// Galois conjugate of an element a in Q[x] / (x^n + 1).
fn galois_conjugate_big(a: &[BigInt]) -> Vec<BigInt> {
    a.iter()
        .enumerate()
        .map(|(i, x)| if i % 2 == 0 { x.clone() } else { -x })
        .collect()
}

/// Field norm: project from Q[x]/(x^n + 1) onto Q[x]/(x^(n/2) + 1).
fn field_norm_big(a: &[BigInt]) -> Vec<BigInt> {
    let n2 = a.len() / 2;
    let ae: Vec<BigInt> = (0..n2).map(|i| a[2 * i].clone()).collect();
    let ao: Vec<BigInt> = (0..n2).map(|i| a[2 * i + 1].clone()).collect();
    let ae_squared = karamul_big(&ae, &ae);
    let ao_squared = karamul_big(&ao, &ao);

    let mut res = ae_squared;
    for i in 0..n2 - 1 {
        res[i + 1] = &res[i + 1] - &ao_squared[i];
    }
    res[0] = &res[0] + &ao_squared[n2 - 1];
    res
}

/// Lift from Q[x]/(x^(n/2) + 1) to Q[x]/(x^n + 1).
fn lift_big(a: &[BigInt]) -> Vec<BigInt> {
    let n = a.len();
    let mut res: Vec<BigInt> = (0..2*n).map(|_| BigInt::zero()).collect();
    for i in 0..n {
        res[2 * i] = a[i].clone();
    }
    res
}

/// Extended GCD of two BigInts.
/// Returns (d, u, v) such that d = u * b + v * n, and d is the GCD.
fn xgcd_big(b: &BigInt, n: &BigInt) -> (BigInt, BigInt, BigInt) {
    let (mut x0, mut x1) = (BigInt::one(), BigInt::zero());
    let (mut y0, mut y1) = (BigInt::zero(), BigInt::one());
    let (mut b, mut n) = (b.clone(), n.clone());

    while !n.is_zero() {
        let q = &b / &n;
        let temp = n.clone();
        n = &b % &n;
        b = temp;

        let temp = x1.clone();
        x1 = &x0 - &q * &x1;
        x0 = temp;

        let temp = y1.clone();
        y1 = &y0 - &q * &y1;
        y0 = temp;
    }
    (b, x0, y0)
}

/// Compute the bitsize of a BigInt (not counting the sign).
/// Rounded to the next multiple of 8.
fn bitsize_big(a: &BigInt) -> i32 {
    let mut val = a.abs();
    let mut res = 0;
    while !val.is_zero() {
        res += 8;
        val >>= 8;
    }
    res
}

/// Reduce (F, G) relatively to (f, g) using Babai's reduction with BigInt precision.
fn reduce_big(f: &[BigInt], g: &[BigInt], f_mut: &mut [BigInt], g_mut: &mut [BigInt]) {
    let n = f.len();

    // Compute size of f, g coefficients
    let size = f
        .iter()
        .chain(g.iter())
        .map(|x| bitsize_big(x))
        .max()
        .unwrap_or(0)
        .max(53);

    // Adjust f, g for finite precision arithmetic
    let f_adjust: Vec<f64> = f.iter().map(|x| (x >> (size - 53)).to_f64().unwrap_or(0.0)).collect();
    let g_adjust: Vec<f64> = g.iter().map(|x| (x >> (size - 53)).to_f64().unwrap_or(0.0)).collect();
    let fa_fft = fft(&f_adjust);
    let ga_fft = fft(&g_adjust);

    loop {
        // Compute size of F, G coefficients
        let cap_size = f_mut
            .iter()
            .chain(g_mut.iter())
            .map(|x| bitsize_big(x))
            .max()
            .unwrap_or(0)
            .max(53);

        if cap_size < size {
            break;
        }

        // Adjust F, G for finite precision arithmetic
        let f_cap_adjust: Vec<f64> = f_mut
            .iter()
            .map(|x| (x >> (cap_size - 53)).to_f64().unwrap_or(0.0))
            .collect();
        let g_cap_adjust: Vec<f64> = g_mut
            .iter()
            .map(|x| (x >> (cap_size - 53)).to_f64().unwrap_or(0.0))
            .collect();
        let fa_cap_fft = fft(&f_cap_adjust);
        let ga_cap_fft = fft(&g_cap_adjust);

        // Compute k = round((F*f* + G*g*) / (f*f* + g*g*))
        let den_fft = add_fft(
            &mul_fft(&fa_fft, &adj_fft(&fa_fft)),
            &mul_fft(&ga_fft, &adj_fft(&ga_fft)),
        );
        let num_fft = add_fft(
            &mul_fft(&fa_cap_fft, &adj_fft(&fa_fft)),
            &mul_fft(&ga_cap_fft, &adj_fft(&ga_fft)),
        );
        let k_fft = div_fft(&num_fft, &den_fft);
        let k_float = ifft(&k_fft);
        let k: Vec<BigInt> = k_float.iter().map(|&x| BigInt::from(x.round() as i64)).collect();

        if k.iter().all(|x| x.is_zero()) {
            break;
        }

        // (F, G) -= k * (f, g)
        let fk = karamul_big(f, &k);
        let gk = karamul_big(g, &k);
        let shift = cap_size - size;

        for i in 0..n {
            f_mut[i] = &f_mut[i] - (&fk[i] << shift);
            g_mut[i] = &g_mut[i] - (&gk[i] << shift);
        }
    }
}

/// Solve the NTRU equation for f and g using BigInt precision.
/// Returns (F, G) such that f*G - g*F = q (mod x^n + 1).
fn ntru_solve_big(f: &[BigInt], g: &[BigInt]) -> Result<(Vec<BigInt>, Vec<BigInt>), ()> {
    let n = f.len();
    if n == 1 {
        let f0 = &f[0];
        let g0 = &g[0];
        let (d, u, v) = xgcd_big(f0, g0);
        if d != BigInt::one() {
            return Err(());
        }
        let q = BigInt::from(Q);
        return Ok((vec![-&q * &v], vec![&q * &u]));
    }

    let fp = field_norm_big(f);
    let gp = field_norm_big(g);
    let (f_prime, g_prime) = ntru_solve_big(&fp, &gp)?;
    let mut f_cap = karamul_big(&lift_big(&f_prime), &galois_conjugate_big(g));
    let mut g_cap = karamul_big(&lift_big(&g_prime), &galois_conjugate_big(f));
    reduce_big(f, g, &mut f_cap, &mut g_cap);
    Ok((f_cap, g_cap))
}

/// Compute the squared Gram-Schmidt norm of the NTRU matrix.
/// This matrix is [[g, -f], [G, -F]].
fn gs_norm(f: &[i32], g: &[i32]) -> f64 {
    // sqnorm of [f, g]
    let sqnorm_fg = sqnorm(&[f, g]);

    // Compute (f*f* + g*g*)
    let f_float: Vec<f64> = f.iter().map(|&x| x as f64).collect();
    let g_float: Vec<f64> = g.iter().map(|&x| x as f64).collect();
    let ffgg = add(&mul(&f_float, &adj(&f_float)), &mul(&g_float, &adj(&g_float)));

    // Ft = adj(g) / (f*f* + g*g*), Gt = adj(f) / (f*f* + g*g*)
    let ft = div(&adj(&g_float), &ffgg);
    let gt = div(&adj(&f_float), &ffgg);

    // sqnorm of [Ft, Gt] * q^2
    let sqnorm_ft_gt: f64 = ft.iter().chain(gt.iter()).map(|&x| x * x).sum();
    let sqnorm_fg_cap = (Q as f64) * (Q as f64) * sqnorm_ft_gt;

    (sqnorm_fg as f64).max(sqnorm_fg_cap)
}

/// Generate a polynomial with coefficients following discrete Gaussian.
fn gen_poly<F: FnMut(usize) -> Vec<u8>>(random_bytes: &mut F) -> [i32; N] {
    const SIGMA: f64 = 1.43300980528773;
    const SIGMIN: f64 = SIGMA - 0.001;
    const OVERSAMPLE: usize = 4096;
    const K: usize = OVERSAMPLE / N;

    let mut f0 = [0i32; OVERSAMPLE];
    for i in 0..OVERSAMPLE {
        f0[i] = samplerz(0.0, SIGMA, SIGMIN, random_bytes);
    }

    let mut f = [0i32; N];
    for i in 0..N {
        let mut sum = 0i32;
        for j in 0..K {
            sum += f0[i * K + j];
        }
        f[i] = sum;
    }
    f
}

/// Generate NTRU polynomials (f, g, F, G) for Falcon.
/// Uses BigInt arithmetic for arbitrary-precision NTRU solving.
pub fn ntru_gen<F: FnMut(usize) -> Vec<u8>>(
    random_bytes: &mut F,
) -> ([i32; N], [i32; N], [i32; N], [i32; N]) {
    loop {
        let f = gen_poly(random_bytes);
        let g = gen_poly(random_bytes);

        // Check Gram-Schmidt norm
        let norm = gs_norm(&f, &g);
        if norm > 1.17 * 1.17 * (Q as f64) {
            continue;
        }

        // Check f is invertible in NTT domain
        let f_ntt = ntt(&f.iter().copied().collect::<Vec<_>>());
        if f_ntt.iter().any(|&x| x == 0) {
            continue;
        }

        // Solve NTRU equation using BigInt precision
        let f_big: Vec<BigInt> = f.iter().map(|&x| BigInt::from(x)).collect();
        let g_big: Vec<BigInt> = g.iter().map(|&x| BigInt::from(x)).collect();
        match ntru_solve_big(&f_big, &g_big) {
            Ok((f_cap, g_cap)) => {
                let mut f_cap_arr = [0i32; N];
                let mut g_cap_arr = [0i32; N];
                for i in 0..N {
                    f_cap_arr[i] = f_cap[i].to_i32().unwrap_or(0);
                    g_cap_arr[i] = g_cap[i].to_i32().unwrap_or(0);
                }
                return (f, g, f_cap_arr, g_cap_arr);
            }
            Err(_) => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_karamul_big() {
        let a: Vec<BigInt> = vec![1, 2].iter().map(|&x| BigInt::from(x)).collect();
        let b: Vec<BigInt> = vec![3, 4].iter().map(|&x| BigInt::from(x)).collect();
        let result = karamul_big(&a, &b);
        assert_eq!(result[0], BigInt::from(-5));
        assert_eq!(result[1], BigInt::from(10));
    }

    #[test]
    fn test_galois_conjugate_big() {
        let a: Vec<BigInt> = vec![1, 2, 3, 4].iter().map(|&x| BigInt::from(x)).collect();
        let conj = galois_conjugate_big(&a);
        assert_eq!(conj[0], BigInt::from(1));
        assert_eq!(conj[1], BigInt::from(-2));
        assert_eq!(conj[2], BigInt::from(3));
        assert_eq!(conj[3], BigInt::from(-4));
    }

    #[test]
    fn test_xgcd_big() {
        let (d, u, v) = xgcd_big(&BigInt::from(35), &BigInt::from(15));
        assert_eq!(d, BigInt::from(5));
        assert_eq!(&u * BigInt::from(35) + &v * BigInt::from(15), BigInt::from(5));
    }
}
