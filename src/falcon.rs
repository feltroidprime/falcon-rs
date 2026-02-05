//! Core Falcon-512 signature scheme.

use crate::common::sqnorm;
use crate::encoding::{compress, decompress, deserialize_public_key, serialize_public_key};
use crate::ffsampling::{ffldl_fft, ffsampling_fft, gram, normalize_tree, LdlTree};
use crate::fft::{add_fft, fft, ifft, mul_fft, Complex};
use crate::hash_to_point::HashToPoint;
use crate::ntrugen::ntru_gen;
use crate::ntt::{div_zq, mul_zq, sub_zq};
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
///
/// Represents the various ways Falcon cryptographic operations can fail.
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
///
/// Contains the NTRU secret polynomials (f, g, F, G) and precomputed
/// values for efficient signing. The secret key is used to produce
/// signatures via lattice-based Gaussian sampling.
///
/// # Security
///
/// The secret key must be kept confidential. Exposure allows an attacker
/// to forge signatures.
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
///
/// Contains the public polynomial h = g/f mod (X^n + 1, q).
/// Used to verify signatures without access to the secret key.
///
/// # Serialization
///
/// The verifying key serializes to 896 bytes (512 coefficients at 14 bits each).
#[derive(Clone)]
pub struct VerifyingKey {
    /// Public key h = g/f mod (x^n + 1, q).
    h: [i32; N],
}

/// Signature for Falcon-512.
///
/// A Falcon signature consists of:
/// - A header byte encoding the parameter set (log2(n))
/// - A random salt (40 bytes)
/// - A compressed polynomial s1
///
/// # Serialization
///
/// The signature serializes to 666 bytes for Falcon-512.
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
    /// Create a verifying key from raw h polynomial.
    pub fn from_h(h: [i32; N]) -> Self {
        VerifyingKey { h }
    }

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
    /// Create a signature from raw components.
    pub fn from_components(header: u8, salt: [u8; SALT_LEN], s1_enc: Vec<u8>) -> Self {
        Signature {
            header,
            salt,
            s1_enc,
        }
    }

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
///
/// The `Falcon` struct provides the core cryptographic operations:
/// key generation, signing, and verification.
///
/// # Type Parameter
///
/// - `H`: The hash function used to map messages to polynomials.
///   Use [`Shake256Hash`](crate::hash_to_point::Shake256Hash) for standard
///   Falcon or [`PoseidonHash`](crate::hash_to_point::PoseidonHash) for
///   Starknet compatibility.
///
/// # Example
///
/// ```rust,ignore
/// use falcon_rs::falcon::Falcon;
/// use falcon_rs::hash_to_point::Shake256Hash;
///
/// let (sk, vk) = Falcon::<Shake256Hash>::keygen();
/// let sig = Falcon::<Shake256Hash>::sign(&sk, b"message");
/// assert!(Falcon::<Shake256Hash>::verify(&vk, b"message", &sig).unwrap());
/// ```
pub struct Falcon<H: HashToPoint> {
    _marker: PhantomData<H>,
}

impl<H: HashToPoint> Falcon<H> {
    /// Generate a new keypair using system randomness.
    ///
    /// Creates a fresh Falcon-512 keypair using the system's cryptographically
    /// secure random number generator.
    ///
    /// # Returns
    ///
    /// A tuple of (secret key, verifying key).
    ///
    /// # Panics
    ///
    /// Panics if the system RNG fails to provide random bytes.
    #[cfg(feature = "shake")]
    pub fn keygen() -> (SecretKey, VerifyingKey) {
        use getrandom::getrandom;
        let mut seed = [0u8; 32];
        getrandom(&mut seed).expect("Failed to get random bytes");
        Self::keygen_with_seed(&seed)
    }

    /// Generate a new keypair with a provided seed.
    ///
    /// Creates a deterministic Falcon-512 keypair from the given seed.
    /// The same seed will always produce the same keypair, which is
    /// useful for testing and key recovery.
    ///
    /// # Arguments
    ///
    /// * `seed` - A seed slice (up to 56 bytes used; shorter seeds are zero-padded)
    ///
    /// # Returns
    ///
    /// A tuple of (secret key, verifying key).
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
    ///
    /// Creates a Falcon-512 keypair using a custom source of randomness.
    /// This is the most flexible key generation method, useful for
    /// deterministic testing or custom RNG implementations.
    ///
    /// # Arguments
    ///
    /// * `random_bytes` - A closure that returns `n` random bytes when called
    ///
    /// # Returns
    ///
    /// A tuple of (secret key, verifying key).
    pub fn keygen_with_rng<F: FnMut(usize) -> Vec<u8>>(
        random_bytes: &mut F,
    ) -> (SecretKey, VerifyingKey) {
        // Generate NTRU polynomials
        let (f, g, capital_f, capital_g) = ntru_gen(random_bytes);

        // Compute public key h = g/f mod (x^n + 1, q)
        let f_vec: Vec<i32> = f.iter().copied().collect();
        let g_vec: Vec<i32> = g.iter().copied().collect();
        let h_vec = div_zq(&g_vec, &f_vec).expect("f should be invertible");
        let mut h = [0i32; N];
        h.copy_from_slice(&h_vec);

        // Compute basis B0 = [[g, -f], [G, -F]] in coefficient representation
        // Note: Use regular negation, NOT modular negation (neg_zq), for the Gram matrix
        let neg_f: Vec<f64> = f_vec.iter().map(|&x| -(x as f64)).collect();
        let neg_f_cap: Vec<f64> = capital_f.iter().map(|&x| -(x as f64)).collect();

        // B0 in coefficient representation (f64 for Gram computation)
        let b0: [[Vec<f64>; 2]; 2] = [
            [g_vec.iter().map(|&x| x as f64).collect(), neg_f],
            [capital_g.iter().map(|&x| x as f64).collect(), neg_f_cap],
        ];

        // Convert B0 to FFT representation (for use in signing)
        let b0_fft = [
            [fft(&b0[0][0]), fft(&b0[0][1])],
            [fft(&b0[1][0]), fft(&b0[1][1])],
        ];

        // Compute Gram matrix G0 = B0 * B0^* in coefficient representation
        // (matching Python's approach: gram() in coef domain, then FFT)
        let g0 = gram(&b0);
        let g0_fft = [
            [fft(&g0[0][0]), fft(&g0[0][1])],
            [fft(&g0[1][0]), fft(&g0[1][1])],
        ];

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
    ///
    /// Creates a Falcon-512 signature over the given message using
    /// the secret key. A fresh random salt is generated for each signature.
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key to sign with
    /// * `message` - The message bytes to sign
    ///
    /// # Returns
    ///
    /// A signature that can be verified with the corresponding verifying key.
    ///
    /// # Panics
    ///
    /// Panics if the system RNG fails to provide random bytes.
    #[cfg(feature = "shake")]
    pub fn sign(sk: &SecretKey, message: &[u8]) -> Signature {
        use getrandom::getrandom;

        // Generate random salt
        let mut salt = [0u8; SALT_LEN];
        getrandom(&mut salt).expect("Failed to get random bytes");

        Self::sign_with_salt(sk, message, &salt)
    }

    /// Sign a message with a provided salt.
    ///
    /// Creates a Falcon-512 signature using a deterministic salt.
    /// This is useful for testing or when reproducible signatures are needed.
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key to sign with
    /// * `message` - The message bytes to sign
    /// * `salt` - A 40-byte salt value
    ///
    /// # Returns
    ///
    /// A signature that can be verified with the corresponding verifying key.
    ///
    /// # Note
    ///
    /// Using the same salt for different messages may leak information
    /// about the secret key. In production, prefer [`sign`](Self::sign).
    pub fn sign_with_salt(sk: &SecretKey, message: &[u8], salt: &[u8; SALT_LEN]) -> Signature {
        let hashed = H::hash_to_point(message, salt);
        let hashed_i32: Vec<i32> = hashed.iter().map(|&x| x as i32).collect();

        // Initialize seed from salt (seed persists across iterations)
        let mut seed = [0u8; SEED_LEN];
        seed[..SALT_LEN].copy_from_slice(salt);

        // Signing loop - repeat until we find a short enough signature
        loop {
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
            // Advance the seed using RNG output
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
            .map(|(&p, &d_i)| {
                Complex::new(
                    p.re * d_i.re / q_f64 - p.im * d_i.im / q_f64,
                    p.re * d_i.im / q_f64 + p.im * d_i.re / q_f64,
                )
            })
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
    ///
    /// Checks that a signature is valid for the given message and verifying key.
    ///
    /// # Arguments
    ///
    /// * `vk` - The verifying key (public key)
    /// * `message` - The message that was supposedly signed
    /// * `sig` - The signature to verify
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the signature is valid
    /// - `Ok(false)` if the signature is mathematically invalid (wrong key or message)
    /// - `Err(FalconError)` if the signature is malformed
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

    // Note: Seed selection matters - some seeds require more NTRU attempts and
    // may hit precision limits in the current i64-based implementation.
    // Seed 42 is known to work reliably.

    #[test]
    fn test_sign_verify_roundtrip() {
        let seed = [42u8; 32];
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
        let seed = [42u8; 32];
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
        let seed = [42u8; 32];
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
