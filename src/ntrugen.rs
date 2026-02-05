//! NTRU key generation for Falcon.

use crate::common::sqnorm;
use crate::fft::{add, adj, adj_fft, add_fft, div, div_fft, fft, ifft, mul, mul_fft};
use crate::ntt::ntt;
use crate::samplerz::samplerz;
use crate::{Q, N};

/// Karatsuba multiplication between polynomials.
/// Returns a polynomial of degree 2n-1 (length 2n).
/// Uses wrapping arithmetic to avoid overflow panics in debug mode.
fn karatsuba(a: &[i64], b: &[i64]) -> Vec<i64> {
    let n = a.len();
    if n == 1 {
        return vec![a[0].wrapping_mul(b[0]), 0];
    }

    let n2 = n / 2;
    let (a0, a1) = a.split_at(n2);
    let (b0, b1) = b.split_at(n2);

    let ax: Vec<i64> = a0.iter().zip(a1).map(|(x, y)| x.wrapping_add(*y)).collect();
    let bx: Vec<i64> = b0.iter().zip(b1).map(|(x, y)| x.wrapping_add(*y)).collect();

    let a0b0 = karatsuba(a0, b0);
    let a1b1 = karatsuba(a1, b1);
    let mut axbx = karatsuba(&ax, &bx);

    for i in 0..n {
        axbx[i] = axbx[i].wrapping_sub(a0b0[i].wrapping_add(a1b1[i]));
    }

    let mut ab = vec![0i64; 2 * n];
    for i in 0..n {
        ab[i] = ab[i].wrapping_add(a0b0[i]);
        ab[i + n] = ab[i + n].wrapping_add(a1b1[i]);
        ab[i + n2] = ab[i + n2].wrapping_add(axbx[i]);
    }
    ab
}

/// Karatsuba multiplication mod (x^n + 1).
fn karamul(a: &[i64], b: &[i64]) -> Vec<i64> {
    let n = a.len();
    let ab = karatsuba(a, b);
    (0..n).map(|i| ab[i].wrapping_sub(ab[i + n])).collect()
}

/// Galois conjugate of an element a in Q[x] / (x^n + 1).
/// The Galois conjugate of a(x) is simply a(-x).
fn galois_conjugate(a: &[i64]) -> Vec<i64> {
    a.iter()
        .enumerate()
        .map(|(i, &x)| if i % 2 == 0 { x } else { -x })
        .collect()
}

/// Project an element a of Q[x] / (x^n + 1) onto Q[x] / (x^(n/2) + 1).
/// This is the field norm.
fn field_norm(a: &[i64]) -> Vec<i64> {
    let n2 = a.len() / 2;
    let ae: Vec<i64> = (0..n2).map(|i| a[2 * i]).collect();
    let ao: Vec<i64> = (0..n2).map(|i| a[2 * i + 1]).collect();
    let ae_squared = karamul(&ae, &ae);
    let ao_squared = karamul(&ao, &ao);

    let mut res = ae_squared;
    for i in 0..n2 - 1 {
        res[i + 1] = res[i + 1].wrapping_sub(ao_squared[i]);
    }
    res[0] = res[0].wrapping_add(ao_squared[n2 - 1]);
    res
}

/// Lift an element a of Q[x] / (x^(n/2) + 1) up to Q[x] / (x^n + 1).
/// The lift of a(x) is simply a(x^2).
fn lift(a: &[i64]) -> Vec<i64> {
    let n = a.len();
    let mut res = vec![0i64; 2 * n];
    for i in 0..n {
        res[2 * i] = a[i];
    }
    res
}

/// Compute the bitsize of an integer (not counting the sign).
/// Rounded to the next multiple of 8 for efficiency.
fn bitsize(a: i64) -> i32 {
    let mut val = a.unsigned_abs();
    let mut res = 0;
    while val != 0 {
        res += 8;
        val >>= 8;
    }
    res
}

/// Reduce (F, G) relatively to (f, g) using Babai's reduction.
/// (F, G) <-- (F, G) - k * (f, g), where k = round((F*f* + G*g*) / (f*f* + g*g*))
fn reduce(f: &[i64], g: &[i64], f_mut: &mut [i64], g_mut: &mut [i64]) {
    let n = f.len();

    // Compute size of f, g coefficients
    let size = f
        .iter()
        .chain(g.iter())
        .map(|&x| bitsize(x))
        .max()
        .unwrap_or(0)
        .max(53);

    // Adjust f, g for finite precision arithmetic
    let f_adjust: Vec<f64> = f.iter().map(|&x| (x >> (size - 53)) as f64).collect();
    let g_adjust: Vec<f64> = g.iter().map(|&x| (x >> (size - 53)) as f64).collect();
    let fa_fft = fft(&f_adjust);
    let ga_fft = fft(&g_adjust);

    loop {
        // Compute size of F, G coefficients
        let cap_size = f_mut
            .iter()
            .chain(g_mut.iter())
            .map(|&x| bitsize(x))
            .max()
            .unwrap_or(0)
            .max(53);

        if cap_size < size {
            break;
        }

        // Adjust F, G for finite precision arithmetic
        let f_cap_adjust: Vec<f64> = f_mut
            .iter()
            .map(|&x| (x >> (cap_size - 53)) as f64)
            .collect();
        let g_cap_adjust: Vec<f64> = g_mut
            .iter()
            .map(|&x| (x >> (cap_size - 53)) as f64)
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
        let k: Vec<i64> = k_float.iter().map(|&x| x.round() as i64).collect();

        if k.iter().all(|&x| x == 0) {
            break;
        }

        // (F, G) -= k * (f, g)
        let fk = karamul(f, &k);
        let gk = karamul(g, &k);
        let shift = cap_size - size;
        for i in 0..n {
            f_mut[i] = f_mut[i].wrapping_sub(fk[i].wrapping_shl(shift as u32));
            g_mut[i] = g_mut[i].wrapping_sub(gk[i].wrapping_shl(shift as u32));
        }
    }
}

/// Extended GCD of two integers b and n.
/// Returns (d, u, v) such that d = u * b + v * n, and d is the GCD.
fn xgcd(b: i64, n: i64) -> (i64, i64, i64) {
    let (mut x0, mut x1, mut y0, mut y1) = (1i64, 0i64, 0i64, 1i64);
    let (mut b, mut n) = (b, n);

    while n != 0 {
        let q = b / n;
        let temp = n;
        n = b % n;
        b = temp;

        let temp = x1;
        x1 = x0.wrapping_sub(q.wrapping_mul(x1));
        x0 = temp;

        let temp = y1;
        y1 = y0.wrapping_sub(q.wrapping_mul(y1));
        y0 = temp;
    }
    (b, x0, y0)
}

/// Solve the NTRU equation for f and g.
/// Returns (F, G) such that f*G - g*F = q (mod x^n + 1).
fn ntru_solve(f: &[i64], g: &[i64]) -> Result<(Vec<i64>, Vec<i64>), ()> {
    let n = f.len();
    if n == 1 {
        let f0 = f[0];
        let g0 = g[0];
        let (d, u, v) = xgcd(f0, g0);
        if d != 1 {
            return Err(());
        }
        let q = Q as i64;
        return Ok((vec![(-q).wrapping_mul(v)], vec![q.wrapping_mul(u)]));
    }

    let fp = field_norm(f);
    let gp = field_norm(g);
    let (f_prime, g_prime) = ntru_solve(&fp, &gp)?;
    let mut f_cap = karamul(&lift(&f_prime), &galois_conjugate(g));
    let mut g_cap = karamul(&lift(&g_prime), &galois_conjugate(f));
    reduce(f, g, &mut f_cap, &mut g_cap);
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
/// Uses sigma_fg = 1.17 * sqrt(q / (2 * n)).
fn gen_poly<F: FnMut(usize) -> Vec<u8>>(random_bytes: &mut F) -> [i32; N] {
    // sigma = 1.17 * sqrt(12289 / 1024) = 1.17 * sqrt(12289) / 32 ≈ 4.05
    // For n=512: sigma = 1.17 * sqrt(12289 / 1024) ≈ 4.05
    // Actually for n=512, we use same technique as Python: sample 4096 gaussians
    // and sum groups of 4096/512 = 8.
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
/// Implements algorithm 5 (NTRUGen) from Falcon's documentation.
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
        let f_ntt = ntt(&f.iter().map(|&x| x).collect::<Vec<_>>());
        if f_ntt.iter().any(|&x| x == 0) {
            continue;
        }

        // Solve NTRU equation
        let f_i64: Vec<i64> = f.iter().map(|&x| x as i64).collect();
        let g_i64: Vec<i64> = g.iter().map(|&x| x as i64).collect();
        match ntru_solve(&f_i64, &g_i64) {
            Ok((f_cap, g_cap)) => {
                let mut f_cap_arr = [0i32; N];
                let mut g_cap_arr = [0i32; N];
                for i in 0..N {
                    f_cap_arr[i] = f_cap[i] as i32;
                    g_cap_arr[i] = g_cap[i] as i32;
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
    fn test_karatsuba() {
        let a = vec![1, 2, 3, 4];
        let b = vec![5, 6, 7, 8];
        let result = karatsuba(&a, &b);
        // (1 + 2x + 3x^2 + 4x^3) * (5 + 6x + 7x^2 + 8x^3)
        // = 5 + 6x + 7x^2 + 8x^3 + 10x + 12x^2 + 14x^3 + 16x^4 + ...
        // = 5 + 16x + 34x^2 + 60x^3 + 61x^4 + 52x^5 + 32x^6
        assert_eq!(result[0], 5);
        assert_eq!(result[1], 16);
        assert_eq!(result[2], 34);
        assert_eq!(result[3], 60);
        assert_eq!(result[4], 61);
        assert_eq!(result[5], 52);
        assert_eq!(result[6], 32);
    }

    #[test]
    fn test_karamul() {
        let a = vec![1, 2];
        let b = vec![3, 4];
        // (1 + 2x) * (3 + 4x) = 3 + 4x + 6x + 8x^2 = 3 + 10x + 8x^2
        // mod (x^2 + 1): 8x^2 becomes -8, so result is (3 - 8) + 10x = -5 + 10x
        let result = karamul(&a, &b);
        assert_eq!(result[0], -5);
        assert_eq!(result[1], 10);
    }

    #[test]
    fn test_galois_conjugate() {
        let a = vec![1, 2, 3, 4];
        let conj = galois_conjugate(&a);
        assert_eq!(conj, vec![1, -2, 3, -4]);
    }

    #[test]
    fn test_xgcd() {
        let (d, u, v) = xgcd(35, 15);
        assert_eq!(d, 5);
        assert_eq!(35 * u + 15 * v, 5);
    }

    #[test]
    fn test_field_norm() {
        // Simple test: field_norm of [1, 0, 0, 0] should be [1, 0]
        let a = vec![1, 0, 0, 0];
        let norm = field_norm(&a);
        assert_eq!(norm.len(), 2);
        assert_eq!(norm[0], 1);
        assert_eq!(norm[1], 0);
    }

    #[test]
    fn test_lift() {
        let a = vec![1, 2];
        let lifted = lift(&a);
        assert_eq!(lifted, vec![1, 0, 2, 0]);
    }
}
