//! WASM bindings for Falcon-512 signature scheme.
//!
//! This module provides JavaScript-friendly bindings for browser use.
//! Currently uses SHAKE256 hash; Poseidon support will be added for Starknet.

#![cfg(feature = "wasm")]

use wasm_bindgen::prelude::*;

use crate::falcon::{Falcon, Signature, VerifyingKey, PUBLIC_KEY_LEN};
use crate::hash_to_point::Shake256Hash;
use crate::SALT_LEN;

/// Generate a new Falcon-512 keypair.
///
/// Returns a JavaScript object with `sk` (secret key bytes) and `vk` (verifying key bytes).
///
/// Note: Key generation is slow (~1-2 minutes) due to NTRU complexity.
#[wasm_bindgen]
pub fn keygen(seed: &[u8]) -> Result<JsValue, JsError> {
    if seed.len() < 32 {
        return Err(JsError::new("Seed must be at least 32 bytes"));
    }

    let (sk, vk) = Falcon::<Shake256Hash>::keygen_with_seed(seed);

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &"sk".into(),
        &js_sys::Uint8Array::from(&sk.to_bytes()[..]),
    )
    .map_err(|e| JsError::new(&format!("Failed to set sk: {:?}", e)))?;
    js_sys::Reflect::set(
        &result,
        &"vk".into(),
        &js_sys::Uint8Array::from(&vk.to_bytes()[..]),
    )
    .map_err(|e| JsError::new(&format!("Failed to set vk: {:?}", e)))?;

    Ok(result.into())
}

/// Sign a message with a secret key.
///
/// Note: This function is a placeholder. Full signing requires the secret key
/// structure which is not easily serializable to JS. Use the native Rust API
/// for signing, or implement a custom serialization format.
#[wasm_bindgen]
pub fn sign(_sk_bytes: &[u8], _message: &[u8], _seed: &[u8]) -> Result<Vec<u8>, JsError> {
    Err(JsError::new(
        "sign() not yet implemented for WASM. Use native Rust API.",
    ))
}

/// Verify a signature.
///
/// Parameters:
/// - `vk_bytes`: The verifying key (public key) bytes
/// - `message`: The signed message
/// - `signature`: The signature bytes
///
/// Returns true if the signature is valid, false otherwise.
#[wasm_bindgen]
pub fn verify(vk_bytes: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsError> {
    if vk_bytes.len() != PUBLIC_KEY_LEN {
        return Err(JsError::new(&format!(
            "Invalid verifying key length: expected {}, got {}",
            PUBLIC_KEY_LEN,
            vk_bytes.len()
        )));
    }

    let vk_arr: [u8; PUBLIC_KEY_LEN] = vk_bytes
        .try_into()
        .map_err(|_| JsError::new("Invalid verifying key"))?;

    let vk = VerifyingKey::from_bytes(&vk_arr).map_err(|e| JsError::new(&e.to_string()))?;

    let sig = Signature::from_bytes(signature).map_err(|e| JsError::new(&e.to_string()))?;

    Falcon::<Shake256Hash>::verify(&vk, message, &sig)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Get the public key length in bytes.
#[wasm_bindgen]
pub fn public_key_length() -> usize {
    PUBLIC_KEY_LEN
}

/// Get the salt length in bytes.
#[wasm_bindgen]
pub fn salt_length() -> usize {
    SALT_LEN
}
