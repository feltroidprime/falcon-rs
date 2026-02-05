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
