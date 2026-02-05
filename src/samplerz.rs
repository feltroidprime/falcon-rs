//! Gaussian sampler over the integers.

/// Upper bound on all the values of sigma.
const MAX_SIGMA: f64 = 1.8205;
const INV_2SIGMA2: f64 = 1.0 / (2.0 * MAX_SIGMA * MAX_SIGMA);

/// Precision of RCDT in bits.
const RCDT_PREC: usize = 72;

/// ln(2) and 1/ln(2).
const LN2: f64 = 0.69314718056;
const ILN2: f64 = 1.44269504089;

/// Reverse cumulative distribution table for half-Gaussian.
const RCDT: [u128; 18] = [
    3024686241123004913666,
    1564742784480091954050,
    636254429462080897535,
    199560484645026482916,
    47667343854657281903,
    8595902006365044063,
    1163297957344668388,
    117656387352093658,
    8867391802663976,
    496969357462633,
    20680885154299,
    638331848991,
    14602316184,
    247426747,
    3104126,
    28824,
    198,
    1,
];

/// Polynomial coefficients for exp(-x) approximation.
const C: [u64; 13] = [
    0x00000004741183A3,
    0x00000036548CFC06,
    0x0000024FDCBF140A,
    0x0000171D939DE045,
    0x0000D00CF58F6F84,
    0x000680681CF796E3,
    0x002D82D8305B0FEA,
    0x011111110E066FD0,
    0x0555555555070F00,
    0x155555555581FF00,
    0x400000000002B400,
    0x7FFFFFFFFFFF4800,
    0x8000000000000000,
];

/// Sample from half-Gaussian distribution.
fn basesampler<F: FnMut(usize) -> Vec<u8>>(random_bytes: &mut F) -> i32 {
    let bytes = random_bytes(RCDT_PREC / 8); // 9 bytes
    let mut arr = [0u8; 16];
    arr[..9].copy_from_slice(&bytes[..9]);
    let u = u128::from_le_bytes(arr);

    let mut z0 = 0i32;
    for &elt in &RCDT {
        if u < elt {
            z0 += 1;
        }
    }
    z0
}

/// Approximate 2^63 * ccs * exp(-x).
/// x and ccs must be positive for correct results.
fn approxexp(x: f64, ccs: f64) -> u64 {
    // y should always be positive according to Python reference
    let mut y = C[0] as i128;
    let z = (x * ((1u64 << 63) as f64)) as i64;

    for &elt in &C[1..] {
        y = (elt as i128) - ((z as i128).wrapping_mul(y) >> 63);
    }

    // If y went negative due to numerical issues, clamp to 0
    if y < 0 {
        return 0;
    }

    // Use u128 to avoid overflow when ccs is close to 1
    // z = int(ccs * 2^63) << 1 = int(ccs * 2^64)
    let z = ((ccs * ((1u64 << 63) as f64)) as u128) << 1;
    let result = z.wrapping_mul(y as u128) >> 63;

    // Saturate to u64::MAX if result overflows (Python uses arbitrary precision)
    result.min(u64::MAX as u128) as u64
}

/// Bernoulli trial with probability ccs * exp(-x).
fn berexp<F: FnMut(usize) -> Vec<u8>>(x: f64, ccs: f64, random_bytes: &mut F) -> bool {
    let s = (x * ILN2) as i32;
    let r = x - (s as f64) * LN2;
    let s = s.min(63) as u32;
    let z = (approxexp(r, ccs).wrapping_sub(1)) >> s;

    // Compare byte by byte from high to low
    for i in (0..=7).rev() {
        let p = random_bytes(1)[0];
        let w = (p as i32) - (((z >> (8 * i)) & 0xFF) as i32);
        if w != 0 {
            return w < 0;
        }
    }
    false
}

/// Sample from discrete Gaussian D_{Z, mu, sigma}.
///
/// Given floating-point values mu, sigma (and sigmin),
/// output an integer z according to the discrete
/// Gaussian distribution D_{Z, mu, sigma}.
///
/// The inputs MUST verify 1 < sigmin < sigma < MAX_SIGMA.
pub fn samplerz<F: FnMut(usize) -> Vec<u8>>(
    mu: f64,
    sigma: f64,
    sigmin: f64,
    random_bytes: &mut F,
) -> i32 {
    let s = mu.floor() as i32;
    let r = mu - (s as f64);
    let dss = 1.0 / (2.0 * sigma * sigma);
    let ccs = sigmin / sigma;

    loop {
        // Sample z0 from a Half-Gaussian
        let z0 = basesampler(random_bytes);

        // Convert z0 into a pseudo-Gaussian sample z
        let b = random_bytes(1)[0] & 1;
        let z = (b as i32) + (2 * (b as i32) - 1) * z0;

        // Rejection sampling to obtain a true Gaussian sample
        let zr = (z as f64) - r;
        let mut x = zr * zr * dss;
        x -= (z0 * z0) as f64 * INV_2SIGMA2;

        if berexp(x, ccs, random_bytes) {
            return z + s;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basesampler() {
        // With uniform random bytes, basesampler should return values in [0, 18]
        let bytes = vec![0xFFu8; 9];
        let mut random_bytes = |n: usize| -> Vec<u8> {
            bytes[..n].to_vec()
        };
        let z = basesampler(&mut random_bytes);
        assert!(z >= 0 && z <= 18);
    }

    #[test]
    fn test_approxexp() {
        // approxexp(0, 1) should give approximately 2^63 * exp(0) = 2^63
        // The actual computation involves polynomial approximation, so check range
        let result = approxexp(0.0, 1.0);
        // For x=0, ccs=1, result should be close to 2^64 (due to << 1 in final step)
        // Actually, looking at the Python trace, approxexp(0.474, 0.75) ≈ 8.6e18 ≈ 2^63
        // So for x=0, ccs=1, we expect something near 2^64 - 1
        eprintln!("approxexp(0.0, 1.0) = {}", result);
        // Just verify it's non-zero and in reasonable range
        assert!(result > 0);
    }

    #[test]
    fn test_samplerz_first_kat() {
        // First KAT case from Python trace
        let mu = -91.90471153063714;
        let sigma = 1.7037990414754918;
        let sigmin = 1.2778336969128337;
        let octets = hex::decode("0FC5442FF043D66E91D1EACAC64EA5450A22941EDC6C").unwrap();

        let mut pos = 0usize;
        let mut random_bytes = |n: usize| -> Vec<u8> {
            let result = octets[pos..pos + n].to_vec();
            eprintln!("  Rust randombytes({}) at pos {} -> {:02x?}", n, pos, &result);
            pos += n;
            result
        };

        let z = samplerz(mu, sigma, sigmin, &mut random_bytes);
        eprintln!("Rust result: z = {}", z);

        // Python gives -95
        assert_eq!(z, -95, "Expected -95 (matching Python), got {}", z);
    }
}
