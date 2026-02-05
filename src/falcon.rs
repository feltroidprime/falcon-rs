//! Core Falcon-512 signature scheme.

use crate::common::sqnorm;
use crate::encoding::{compress, decompress, deserialize_public_key, serialize_public_key};
use crate::fft::{add_fft, fft, ifft, mul_fft, Complex};
use crate::ffsampling::{ffldl_fft, ffsampling_fft, gram, normalize_tree, LdlTree};
use crate::hash_to_point::HashToPoint;
use crate::ntt::{div_zq, mul_zq, neg_zq, sub_zq};
use crate::ntrugen::ntru_gen;
use crate::rng::ChaCha20;
use crate::{N, Q, SALT_LEN, SEED_LEN};
use std::marker::PhantomData;

/// Falcon-512 parameters.
const SIGMA: f64 = 165.7366171829776;
const SIGMIN: f64 = 1.2778336969128337;
const SIG_BOUND: i64 = 34034726;
const SIG_BYTELEN: usize = 666;
const HEAD_LEN: usize = 1;
const LOGN: u8 = 9; // log2(512)

/// Public key byte length (512 * 14 bits / 8 = 896 bytes).
pub const PUBLIC_KEY_LEN: usize = 896;

/// Signature byte length (header + salt + compressed s1).
pub const SIGNATURE_LEN: usize = SIG_BYTELEN;

/// Error type for Falcon operations.
#[derive(Debug, Clone, PartialEq)]
pub enum FalconError {
    InvalidPublicKey,
    InvalidSignature,
    InvalidSecretKey,
    SignatureNormTooLarge,
    DecompressionFailed,
}

impl std::fmt::Display for FalconError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FalconError::InvalidPublicKey => write!(f, "Invalid public key"),
            FalconError::InvalidSignature => write!(f, "Invalid signature"),
            FalconError::InvalidSecretKey => write!(f, "Invalid secret key"),
            FalconError::SignatureNormTooLarge => write!(f, "Signature norm too large"),
            FalconError::DecompressionFailed => write!(f, "Signature decompression failed"),
        }
    }
}

impl std::error::Error for FalconError {}

/// Secret key for Falcon-512.
pub struct SecretKey {
    /// NTRU secret polynomial f.
    f: [i32; N],
    /// NTRU secret polynomial g.
    g: [i32; N],
    /// NTRU secret polynomial F.
    capital_f: [i32; N],
    /// NTRU secret polynomial G.
    capital_g: [i32; N],
    /// Basis B0 in FFT representation.
    b0_fft: [[Vec<Complex>; 2]; 2],
    /// LDL tree for fast sampling.
    tree: LdlTree,
}

/// Verifying key (public key) for Falcon-512.
#[derive(Clone)]
pub struct VerifyingKey {
    /// Public key h = g/f mod (x^n + 1, q).
    h: [i32; N],
}

/// Signature for Falcon-512.
pub struct Signature {
    /// Header byte (encodes log(n)).
    header: u8,
    /// Random salt.
    salt: [u8; SALT_LEN],
    /// Compressed signature polynomial s1.
    s1_enc: Vec<u8>,
}

impl SecretKey {
    /// Serialize the secret key to bytes.
    ///
    /// Format: f || g || F || G (4 polynomials, each 896 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 * PUBLIC_KEY_LEN);
        bytes.extend_from_slice(&serialize_public_key(&self.f));
        bytes.extend_from_slice(&serialize_public_key(&self.g));
        bytes.extend_from_slice(&serialize_public_key(&self.capital_f));
        bytes.extend_from_slice(&serialize_public_key(&self.capital_g));
        bytes
    }
}

impl VerifyingKey {
    /// Serialize the verifying key to bytes.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        let vec = serialize_public_key(&self.h);
        let mut arr = [0u8; PUBLIC_KEY_LEN];
        arr.copy_from_slice(&vec);
        arr
    }

    /// Deserialize a verifying key from bytes.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<Self, FalconError> {
        let h = deserialize_public_key(bytes).ok_or(FalconError::InvalidPublicKey)?;
        Ok(VerifyingKey { h })
    }
}

impl Signature {
    /// Serialize the signature to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEAD_LEN + SALT_LEN + self.s1_enc.len());
        bytes.push(self.header);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.s1_enc);
        bytes
    }

    /// Deserialize a signature from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FalconError> {
        if bytes.len() < HEAD_LEN + SALT_LEN {
            return Err(FalconError::InvalidSignature);
        }

        let header = bytes[0];
        if header != 0x30 + LOGN {
            return Err(FalconError::InvalidSignature);
        }

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[HEAD_LEN..HEAD_LEN + SALT_LEN]);

        let s1_enc = bytes[HEAD_LEN + SALT_LEN..].to_vec();

        Ok(Signature {
            header,
            salt,
            s1_enc,
        })
    }
}

/// Falcon-512 signature scheme parameterized by hash function.
pub struct Falcon<H: HashToPoint> {
    _marker: PhantomData<H>,
}

impl<H: HashToPoint> Falcon<H> {
    /// Generate a new keypair using system randomness.
    #[cfg(feature = "shake")]
    pub fn keygen() -> (SecretKey, VerifyingKey) {
        use getrandom::getrandom;
        let mut seed = [0u8; 32];
        getrandom(&mut seed).expect("Failed to get random bytes");
        Self::keygen_with_seed(&seed)
    }

    /// Generate a new keypair with a provided seed.
    pub fn keygen_with_seed(seed: &[u8]) -> (SecretKey, VerifyingKey) {
        // Create a deterministic RNG from the seed
        let mut full_seed = [0u8; SEED_LEN];
        let copy_len = seed.len().min(SEED_LEN);
        full_seed[..copy_len].copy_from_slice(&seed[..copy_len]);
        let mut rng = ChaCha20::new(&full_seed);
        let mut random_bytes = |n: usize| rng.random_bytes(n);

        Self::keygen_with_rng(&mut random_bytes)
    }

    /// Generate a new keypair with a provided random byte source.
    pub fn keygen_with_rng<F: FnMut(usize) -> Vec<u8>>(random_bytes: &mut F) -> (SecretKey, VerifyingKey) {
        // Generate NTRU polynomials
        let (f, g, capital_f, capital_g) = ntru_gen(random_bytes);

        // Compute public key h = g/f mod (x^n + 1, q)
        let f_vec: Vec<i32> = f.iter().copied().collect();
        let g_vec: Vec<i32> = g.iter().copied().collect();
        let h_vec = div_zq(&g_vec, &f_vec).expect("f should be invertible");
        let mut h = [0i32; N];
        h.copy_from_slice(&h_vec);

        // Compute basis B0 = [[g, -f], [G, -F]]
        let neg_f: Vec<i32> = neg_zq(&f_vec);
        let neg_f_cap: Vec<i32> = neg_zq(&capital_f.iter().map(|&x| x).collect::<Vec<_>>());

        let b0 = [
            [g_vec.clone(), neg_f.clone()],
            [capital_g.iter().map(|&x| x).collect::<Vec<_>>(), neg_f_cap],
        ];

        // Convert B0 to FFT representation
        let b0_fft = [
            [
                fft(&b0[0][0].iter().map(|&x| x as f64).collect::<Vec<_>>()),
                fft(&b0[0][1].iter().map(|&x| x as f64).collect::<Vec<_>>()),
            ],
            [
                fft(&b0[1][0].iter().map(|&x| x as f64).collect::<Vec<_>>()),
                fft(&b0[1][1].iter().map(|&x| x as f64).collect::<Vec<_>>()),
            ],
        ];

        // Compute Gram matrix G0 = B0 * B0^*
        let g0_fft = gram(&b0_fft);

        // Build ffLDL tree
        let mut tree = ffldl_fft(&g0_fft);
        normalize_tree(&mut tree, SIGMA);

        let sk = SecretKey {
            f,
            g,
            capital_f,
            capital_g,
            b0_fft,
            tree,
        };

        let vk = VerifyingKey { h };

        (sk, vk)
    }

    /// Sign a message.
    #[cfg(feature = "shake")]
    pub fn sign(sk: &SecretKey, message: &[u8]) -> Signature {
        use getrandom::getrandom;

        // Generate random salt
        let mut salt = [0u8; SALT_LEN];
        getrandom(&mut salt).expect("Failed to get random bytes");

        Self::sign_with_salt(sk, message, &salt)
    }

    /// Sign a message with a provided salt.
    pub fn sign_with_salt(sk: &SecretKey, message: &[u8], salt: &[u8; SALT_LEN]) -> Signature {
        let hashed = H::hash_to_point(message, salt);
        let hashed_i32: Vec<i32> = hashed.iter().map(|&x| x as i32).collect();

        // Signing loop - repeat until we find a short enough signature
        loop {
            // Create deterministic RNG from message hash and counter
            // In practice, we'd use a proper seed derivation
            let mut seed = [0u8; SEED_LEN];
            seed[..SALT_LEN].copy_from_slice(salt);
            let mut rng = ChaCha20::new(&seed);
            let mut random_bytes = |n: usize| rng.random_bytes(n);

            // Sample preimage
            let (s0, s1) = Self::sample_preimage(sk, &hashed_i32, &mut random_bytes);

            // Check Euclidean norm
            let s0_slice: &[i32] = &s0;
            let s1_slice: &[i32] = &s1;
            let norm = sqnorm(&[s0_slice, s1_slice]);

            if norm <= SIG_BOUND {
                // Try to compress s1
                let slen = SIG_BYTELEN - HEAD_LEN - SALT_LEN;
                if let Some(s1_enc) = compress(&s1, slen) {
                    return Signature {
                        header: 0x30 + LOGN,
                        salt: *salt,
                        s1_enc,
                    };
                }
            }

            // If norm too large or compression failed, try again with different randomness
            // Advance the RNG state
            seed[SALT_LEN..].copy_from_slice(&rng.random_bytes(SEED_LEN - SALT_LEN)[..]);
        }
    }

    /// Sample a short preimage s such that s0 + s1*h = point.
    fn sample_preimage<F: FnMut(usize) -> Vec<u8>>(
        sk: &SecretKey,
        point: &[i32],
        random_bytes: &mut F,
    ) -> (Vec<i32>, Vec<i32>) {
        let [[a, b], [c, d]] = &sk.b0_fft;

        // Compute t_fft = (point, 0) * B0^(-1)
        // Because the inverse of B0 has a specific form, we can optimize
        let point_fft = fft(&point.iter().map(|&x| x as f64).collect::<Vec<_>>());
        let q_f64 = Q as f64;

        let t0_fft: Vec<Complex> = point_fft
            .iter()
            .zip(d.iter())
            .map(|(&p, &d_i)| Complex::new(p.re * d_i.re / q_f64 - p.im * d_i.im / q_f64,
                                           p.re * d_i.im / q_f64 + p.im * d_i.re / q_f64))
            .collect();

        let t1_fft: Vec<Complex> = point_fft
            .iter()
            .zip(b.iter())
            .map(|(&p, &b_i)| {
                let neg_p = Complex::new(-p.re, -p.im);
                Complex::new(
                    (neg_p.re * b_i.re - neg_p.im * b_i.im) / q_f64,
                    (neg_p.re * b_i.im + neg_p.im * b_i.re) / q_f64,
                )
            })
            .collect();

        let t_fft = [t0_fft, t1_fft];

        // Sample z using ffsampling
        let z_fft = ffsampling_fft(&t_fft, &sk.tree, SIGMIN, random_bytes);

        // Compute v = z * B0
        let v0_fft = add_fft(&mul_fft(&z_fft[0], a), &mul_fft(&z_fft[1], c));
        let v1_fft = add_fft(&mul_fft(&z_fft[0], b), &mul_fft(&z_fft[1], d));

        let v0_float = ifft(&v0_fft);
        let v1_float = ifft(&v1_fft);

        let v0: Vec<i32> = v0_float.iter().map(|&x| x.round() as i32).collect();
        let v1: Vec<i32> = v1_float.iter().map(|&x| x.round() as i32).collect();

        // s = (point, 0) - v
        // s0 = point - v0, s1 = -v1
        let s0: Vec<i32> = point.iter().zip(v0.iter()).map(|(&p, &v)| p - v).collect();
        let s1: Vec<i32> = v1.iter().map(|&v| -v).collect();

        (s0, s1)
    }

    /// Verify a signature.
    pub fn verify(vk: &VerifyingKey, message: &[u8], sig: &Signature) -> Result<bool, FalconError> {
        // Decompress s1
        let s1 = decompress(&sig.s1_enc, N).ok_or(FalconError::DecompressionFailed)?;

        // Hash the message
        let hashed = H::hash_to_point(message, &sig.salt);
        let hashed_i32: Vec<i32> = hashed.iter().map(|&x| x as i32).collect();

        // Compute s0 = hashed - s1 * h
        let h_vec: Vec<i32> = vk.h.iter().copied().collect();
        let s1_h = mul_zq(&s1, &h_vec);
        let s0 = sub_zq(&hashed_i32, &s1_h);

        // Normalize s0 coefficients to (-q/2, q/2]
        let s0_centered: Vec<i32> = s0
            .iter()
            .map(|&c| {
                let c = c.rem_euclid(Q);
                if c > Q / 2 {
                    c - Q
                } else {
                    c
                }
            })
            .collect();

        // Check signature norm
        let s0_slice: &[i32] = &s0_centered;
        let s1_slice: &[i32] = &s1;
        let norm = sqnorm(&[s0_slice, s1_slice]);

        if norm > SIG_BOUND {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(all(test, feature = "shake"))]
mod tests {
    use super::*;
    use crate::hash_to_point::Shake256Hash;

    #[test]
    fn test_keygen_deterministic() {
        let seed = [42u8; 32];
        let (sk1, vk1) = Falcon::<Shake256Hash>::keygen_with_seed(&seed);
        let (sk2, vk2) = Falcon::<Shake256Hash>::keygen_with_seed(&seed);

        assert_eq!(sk1.f, sk2.f);
        assert_eq!(sk1.g, sk2.g);
        assert_eq!(vk1.h, vk2.h);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let seed = [123u8; 32];
        let (sk, vk) = Falcon::<Shake256Hash>::keygen_with_seed(&seed);

        let message = b"Hello, Falcon!";
        let salt = [0u8; SALT_LEN];
        let sig = Falcon::<Shake256Hash>::sign_with_salt(&sk, message, &salt);

        let result = Falcon::<Shake256Hash>::verify(&vk, message, &sig);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_wrong_message() {
        let seed = [123u8; 32];
        let (sk, vk) = Falcon::<Shake256Hash>::keygen_with_seed(&seed);

        let message = b"Hello, Falcon!";
        let salt = [0u8; SALT_LEN];
        let sig = Falcon::<Shake256Hash>::sign_with_salt(&sk, message, &salt);

        let wrong_message = b"Wrong message!";
        let result = Falcon::<Shake256Hash>::verify(&vk, wrong_message, &sig);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_signature_serialization() {
        let seed = [123u8; 32];
        let (sk, vk) = Falcon::<Shake256Hash>::keygen_with_seed(&seed);

        let message = b"Test message";
        let salt = [1u8; SALT_LEN];
        let sig = Falcon::<Shake256Hash>::sign_with_salt(&sk, message, &salt);

        let bytes = sig.to_bytes();
        let sig2 = Signature::from_bytes(&bytes).unwrap();

        assert_eq!(sig.header, sig2.header);
        assert_eq!(sig.salt, sig2.salt);
        assert_eq!(sig.s1_enc, sig2.s1_enc);

        // Verify the deserialized signature
        let result = Falcon::<Shake256Hash>::verify(&vk, message, &sig2);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_public_key_serialization() {
        let seed = [42u8; 32];
        let (_, vk) = Falcon::<Shake256Hash>::keygen_with_seed(&seed);

        let bytes = vk.to_bytes();
        let vk2 = VerifyingKey::from_bytes(&bytes).unwrap();

        assert_eq!(vk.h, vk2.h);
    }
}
