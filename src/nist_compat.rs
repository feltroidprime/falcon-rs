//! NIST format compatibility for Falcon signatures.

use crate::falcon::{FalconError, Signature, VerifyingKey};
use crate::{N, Q, SALT_LEN};

/// NIST KAT constants for Falcon-512.
const NIST_SIG_HEADER: u8 = 0x29; // 0x20 + 9 (logn for n=512)
const NIST_PK_HEADER: u8 = 0x09; // 0x00 + 9
const NIST_PK_LEN: usize = 897; // 1 header + 896 body
const NONCELEN: usize = 40;

/// Parsed components from NIST signed-message format.
pub struct NistSmComponents {
    /// The nonce/salt (40 bytes).
    pub nonce: [u8; SALT_LEN],
    /// The original message.
    pub message: Vec<u8>,
    /// The compressed s1 polynomial (without header).
    pub compressed_s1: Vec<u8>,
}

/// Parse NIST signed-message format.
///
/// NIST sm format:
///     [sig_len: 2B BE] [nonce: 40B] [message: msg_len B] [signature: sig_len B]
pub fn parse_nist_sm(sm: &[u8]) -> Result<NistSmComponents, FalconError> {
    if sm.len() < 44 {
        return Err(FalconError::InvalidSignature);
    }

    let sig_len = ((sm[0] as usize) << 8) | (sm[1] as usize);

    if sm.len() < 2 + NONCELEN + sig_len {
        return Err(FalconError::InvalidSignature);
    }

    let msg_len = sm.len() - 2 - NONCELEN - sig_len;

    let mut nonce = [0u8; SALT_LEN];
    nonce.copy_from_slice(&sm[2..42]);

    let message = sm[42..42 + msg_len].to_vec();
    let signature = &sm[42 + msg_len..];

    if signature.len() != sig_len {
        return Err(FalconError::InvalidSignature);
    }

    if signature[0] != NIST_SIG_HEADER {
        return Err(FalconError::InvalidSignature);
    }

    let compressed_s1 = signature[1..].to_vec();

    Ok(NistSmComponents {
        nonce,
        message,
        compressed_s1,
    })
}

/// Parse NIST public key format and extract the raw 896 bytes.
pub fn parse_nist_pk_bytes(pk: &[u8]) -> Result<&[u8], FalconError> {
    if pk.len() != NIST_PK_LEN {
        return Err(FalconError::InvalidPublicKey);
    }

    if pk[0] != NIST_PK_HEADER {
        return Err(FalconError::InvalidPublicKey);
    }

    Ok(&pk[1..])
}

/// Deserialize NIST public key using big-endian bit packing.
///
/// NIST uses big-endian (MSB-first) 14-bit packing, different from
/// falcon-rs's little-endian packing.
pub fn deserialize_nist_pk(pk_bytes: &[u8]) -> Result<[i32; N], FalconError> {
    if pk_bytes.len() != 896 {
        return Err(FalconError::InvalidPublicKey);
    }

    let mut poly = [0i32; N];
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mut byte_idx = 0;
    let mut coef_idx = 0;

    while coef_idx < N {
        acc = (acc << 8) | (pk_bytes[byte_idx] as u32);
        byte_idx += 1;
        acc_len += 8;

        if acc_len >= 14 {
            acc_len -= 14;
            let w = (acc >> acc_len) & 0x3FFF;
            if w >= Q as u32 {
                return Err(FalconError::InvalidPublicKey);
            }
            poly[coef_idx] = w as i32;
            coef_idx += 1;
        }
    }

    Ok(poly)
}

/// Parse NIST public key and create a VerifyingKey.
pub fn parse_nist_pk(pk: &[u8]) -> Result<VerifyingKey, FalconError> {
    let pk_bytes = parse_nist_pk_bytes(pk)?;
    let h = deserialize_nist_pk(pk_bytes)?;
    Ok(VerifyingKey::from_h(h))
}

/// Create a Signature from NIST components for use with falcon-rs verify.
pub fn nist_to_falcon_signature(nonce: [u8; SALT_LEN], compressed_s1: Vec<u8>) -> Signature {
    const FALCON_SIG_HEADER: u8 = 0x39; // 0x30 + 9
    Signature::from_components(FALCON_SIG_HEADER, nonce, compressed_s1)
}

/// NIST secret key format constants for Falcon-512.
const NIST_SK_HEADER: u8 = 0x59; // 0x50 + 9 (logn for n=512)
const NIST_SK_F_LEN: usize = 384; // 6-bit trim_i8 encoding for n=512: (512 * 6 + 7) / 8 = 384
const NIST_SK_G_LEN: usize = 384; // same as f
const NIST_SK_F_UPPER_LEN: usize = 512; // 8-bit trim_i8 encoding for n=512: 512 * 8 / 8 = 512
const NIST_SK_LEN: usize = 1 + NIST_SK_F_LEN + NIST_SK_G_LEN + NIST_SK_F_UPPER_LEN; // 1281 bytes

/// Decode NIST trim_i8 format (signed integers packed into bits).
///
/// This decodes data packed with `bits` bits per coefficient, where values
/// are stored as signed integers in two's complement within the bit width.
pub fn trim_i8_decode(data: &[u8], n: usize, bits: usize) -> Result<Vec<i32>, FalconError> {
    let expected_len = (n * bits + 7) / 8;
    if data.len() != expected_len {
        return Err(FalconError::InvalidSecretKey);
    }

    let mut result = Vec::with_capacity(n);
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mut byte_idx = 0;

    let mask = (1u32 << bits) - 1;
    let sign_bit = 1u32 << (bits - 1);

    for _ in 0..n {
        // Accumulate bytes until we have enough bits
        while acc_len < bits as u32 {
            acc = (acc << 8) | (data[byte_idx] as u32);
            byte_idx += 1;
            acc_len += 8;
        }

        // Extract the value
        acc_len -= bits as u32;
        let val = (acc >> acc_len) & mask;

        // Sign extend if needed
        let signed_val = if val >= sign_bit {
            (val as i32) - (1i32 << bits)
        } else {
            val as i32
        };

        result.push(signed_val);
    }

    Ok(result)
}

/// Parse NIST secret key format to extract f, g, F polynomials.
///
/// NIST sk format for Falcon-512:
///     [header: 1B] [f: 384B] [g: 384B] [F: 512B]
///
/// Where:
/// - header = 0x59 (0x50 + 9 for n=512)
/// - f, g: 6-bit trim_i8 encoding
/// - F: 8-bit trim_i8 encoding
pub fn parse_nist_sk(sk: &[u8]) -> Result<([i32; N], [i32; N], [i32; N]), FalconError> {
    if sk.len() != NIST_SK_LEN {
        return Err(FalconError::InvalidSecretKey);
    }

    if sk[0] != NIST_SK_HEADER {
        return Err(FalconError::InvalidSecretKey);
    }

    let f_bytes = &sk[1..1 + NIST_SK_F_LEN];
    let g_bytes = &sk[1 + NIST_SK_F_LEN..1 + NIST_SK_F_LEN + NIST_SK_G_LEN];
    let f_upper_bytes = &sk[1 + NIST_SK_F_LEN + NIST_SK_G_LEN..];

    let f_vec = trim_i8_decode(f_bytes, N, 6)?;
    let g_vec = trim_i8_decode(g_bytes, N, 6)?;
    let f_upper_vec = trim_i8_decode(f_upper_bytes, N, 8)?;

    let mut f = [0i32; N];
    let mut g = [0i32; N];
    let mut f_upper = [0i32; N];

    f.copy_from_slice(&f_vec);
    g.copy_from_slice(&g_vec);
    f_upper.copy_from_slice(&f_upper_vec);

    Ok((f, g, f_upper))
}

/// Serialize public key in NIST big-endian format.
///
/// NIST uses big-endian (MSB-first) 14-bit packing.
pub fn serialize_nist_pk(h: &[i32; N]) -> Vec<u8> {
    let mut result = Vec::with_capacity(NIST_PK_LEN);
    result.push(NIST_PK_HEADER);

    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;

    for &coef in h.iter() {
        // Ensure coefficient is in valid range [0, Q)
        let val = coef.rem_euclid(Q) as u32;

        // Accumulate 14 bits
        acc = (acc << 14) | val;
        acc_len += 14;

        // Write complete bytes
        while acc_len >= 8 {
            acc_len -= 8;
            result.push((acc >> acc_len) as u8);
        }
    }

    // Handle any remaining bits (should be none for 512 coefficients)
    if acc_len > 0 {
        result.push((acc << (8 - acc_len)) as u8);
    }

    result
}
