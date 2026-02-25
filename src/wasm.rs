//! WASM bindings for Falcon-512 signature scheme.
//!
//! This module provides JavaScript-friendly bindings for browser use.
//! Currently uses SHAKE256 hash; Poseidon support will be added for Starknet.

#![cfg(feature = "wasm")]

use wasm_bindgen::prelude::*;

use crate::falcon::{Falcon, SecretKey, Signature, VerifyingKey, PUBLIC_KEY_LEN};
use crate::hash_to_point::Shake256Hash;
use crate::hints::generate_mul_hint;
use crate::packing::pack_public_key;
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
/// Parameters:
/// - `sk_bytes`: The secret key bytes (serialized as 4 × 896 = 3584 bytes via `SecretKey::to_bytes`)
/// - `message`: The message to sign
/// - `salt`: A 40-byte random salt (must be exactly `SALT_LEN` bytes)
///
/// Returns a JavaScript object with:
/// - `signature`: `Uint8Array` of 666 bytes (the full Falcon-512 signature)
/// - `salt`: `Uint8Array` of 40 bytes (echo of the provided salt)
///
/// # Notes
///
/// The caller is responsible for generating a cryptographically random `salt` before
/// calling this function. The same salt must not be reused for different messages.
#[wasm_bindgen]
pub fn sign(sk_bytes: &[u8], message: &[u8], salt: &[u8]) -> Result<JsValue, JsError> {
    // Validate salt length
    if salt.len() != SALT_LEN {
        return Err(JsError::new(&format!(
            "Invalid salt length: expected {SALT_LEN}, got {}",
            salt.len()
        )));
    }
    let salt_arr: [u8; SALT_LEN] = salt
        .try_into()
        .map_err(|_| JsError::new("Failed to convert salt to fixed-size array"))?;

    // Deserialize the secret key (reconstructs b0_fft and LDL tree)
    let sk = SecretKey::from_bytes(sk_bytes).map_err(|e| JsError::new(&e.to_string()))?;

    // Sign the message with the provided salt
    let sig = Falcon::<Shake256Hash>::sign_with_salt(&sk, message, &salt_arr);

    // Build return object: { signature: Uint8Array, salt: Uint8Array }
    let result = js_sys::Object::new();

    js_sys::Reflect::set(
        &result,
        &"signature".into(),
        &js_sys::Uint8Array::from(&sig.to_bytes()[..]),
    )
    .map_err(|e| JsError::new(&format!("Failed to set signature: {e:?}")))?;

    js_sys::Reflect::set(
        &result,
        &"salt".into(),
        &js_sys::Uint8Array::from(sig.salt().as_slice()),
    )
    .map_err(|e| JsError::new(&format!("Failed to set salt: {e:?}")))?;

    Ok(result.into())
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

    Falcon::<Shake256Hash>::verify(&vk, message, &sig).map_err(|e| JsError::new(&e.to_string()))
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

/// Create a verification hint for Cairo on-chain verification.
///
/// Computes `INTT(NTT(s1) * pk_ntt)` — the mul_hint that allows
/// Cairo to verify NTT products with 2 forward NTTs and 0 INTTs.
///
/// Parameters:
/// - `s1`: 512 signature coefficients (each in [0, 12289))
/// - `pk_ntt`: 512 public key NTT coefficients (each in [0, 12289))
///
/// Returns: Vec of 512 hint coefficients (returned as Uint16Array to JS).
#[wasm_bindgen]
pub fn create_verification_hint(s1: &[i32], pk_ntt: &[i32]) -> Result<Vec<u16>, JsError> {
    if s1.len() != 512 {
        return Err(JsError::new(&format!(
            "Invalid s1 length: expected 512, got {}",
            s1.len()
        )));
    }
    if pk_ntt.len() != 512 {
        return Err(JsError::new(&format!(
            "Invalid pk_ntt length: expected 512, got {}",
            pk_ntt.len()
        )));
    }

    let s1_u16: Vec<u16> = s1.iter().map(|&v| v as u16).collect();
    let pk_u16: Vec<u16> = pk_ntt.iter().map(|&v| v as u16).collect();

    Ok(generate_mul_hint(&s1_u16, &pk_u16))
}

/// Pack a public key (512 Zq values) into 29 felt252 storage slots.
///
/// Uses base-Q Horner encoding: 18 values per felt252 (9 per u128 half).
/// This achieves a 17x calldata reduction (512 → 29 slots).
///
/// Parameters:
/// - `pk_ntt`: 512 public key NTT coefficients (each in [0, 12289))
///
/// Returns: Array of 29 hex strings, each representing a felt252.
#[wasm_bindgen]
pub fn pack_public_key_wasm(pk_ntt: &[u16]) -> Result<Vec<String>, JsError> {
    if pk_ntt.len() != 512 {
        return Err(JsError::new(&format!(
            "Invalid pk_ntt length: expected 512, got {}",
            pk_ntt.len()
        )));
    }

    let packed = pack_public_key(pk_ntt);
    Ok(packed.iter().map(|f| format!("0x{}", f.to_hex())).collect())
}

/// Sign a Starknet transaction hash using Falcon-512 with Poseidon hash-to-point.
///
/// This produces a signature in the format expected by the Cairo FalconAccount contract:
/// - 29 packed felt252 for s1 (signature polynomial)
/// - 29 packed felt252 for mul_hint (verification hint)
/// - 2 felt252 for the salt
/// - 1 felt252 for the salt length
/// Total: 61 felt252 elements.
///
/// Parameters:
/// - `sk_bytes`: Secret key bytes (serialized SecretKey)
/// - `tx_hash`: Transaction hash as hex string (felt252)
/// - `pk_ntt`: 512 public key NTT coefficients (each in [0, 12289))
///
/// Returns: Array of 61 hex strings, each representing a felt252.
#[wasm_bindgen]
pub fn sign_for_starknet(
    sk_bytes: &[u8],
    tx_hash: &str,
    pk_ntt: &[i32],
) -> Result<Vec<String>, JsError> {
    use crate::hash_to_point::HashToPoint;
    use crate::poseidon_hash::{Felt, PoseidonHashToPoint};

    if pk_ntt.len() != 512 {
        return Err(JsError::new(&format!(
            "Invalid pk_ntt length: expected 512, got {}",
            pk_ntt.len()
        )));
    }

    // 1. Deserialize secret key
    let sk = SecretKey::from_bytes(sk_bytes)
        .map_err(|e| JsError::new(&format!("Invalid secret key: {e}")))?;

    // 2. Parse tx_hash as felt252
    let tx_hash_felt = Felt::from_hex(tx_hash)
        .map_err(|_| JsError::new(&format!("Invalid tx_hash hex: {tx_hash}")))?;

    // 3. Generate random salt (2 felt252 values)
    let salt_bytes = getrandom_salt()?;
    let salt_felt0 = Felt::from_hex(&format!("0x{}", bytes_to_hex(&salt_bytes[..31])))
        .map_err(|_| JsError::new("Failed to create salt felt 0"))?;
    let salt_felt1 = Felt::from_hex(&format!("0x{}", bytes_to_hex(&salt_bytes[31..62])))
        .map_err(|_| JsError::new("Failed to create salt felt 1"))?;
    let salt = vec![salt_felt0, salt_felt1];

    // 4. Compute msg_point = PoseidonHashToPoint([tx_hash], salt)
    let message = vec![tx_hash_felt];
    let msg_point = PoseidonHashToPoint::hash_to_point(&message, &salt);

    // 5. Sign the prehashed point
    let sign_seed = {
        let mut s = [0u8; crate::SEED_LEN];
        s[..crate::SALT_LEN].copy_from_slice(&salt_bytes[..crate::SALT_LEN]);
        s
    };
    let (_s0, s1) = Falcon::<PoseidonHashToPoint>::sign_prehashed(&sk, &msg_point, &sign_seed);

    // 6. Convert s1 to u16 (unsigned mod Q)
    let s1_u16: Vec<u16> = s1.iter().map(|&v| v.rem_euclid(crate::Q) as u16).collect();

    // 7. Convert pk_ntt to u16
    let pk_u16: Vec<u16> = pk_ntt.iter().map(|&v| v.rem_euclid(crate::Q) as u16).collect();

    // 8. Compute mul_hint = INTT(NTT(s1) * pk_ntt)
    let mul_hint = generate_mul_hint(&s1_u16, &pk_u16);

    // 9. Pack s1 into 29 felt252
    let packed_s1 = pack_public_key(&s1_u16);

    // 10. Pack mul_hint into 29 felt252
    let packed_hint = pack_public_key(&mul_hint);

    // 11. Build output: [packed_s1(29), packed_hint(29), salt(2), salt_len(1)] = 61 elements
    let mut result: Vec<String> = Vec::with_capacity(61);
    for f in &packed_s1 {
        result.push(format!("0x{}", f.to_hex()));
    }
    for f in &packed_hint {
        result.push(format!("0x{}", f.to_hex()));
    }
    for f in &salt {
        result.push(format!("0x{}", f.to_hex()));
    }
    // Salt length as felt252
    result.push(format!("0x{:x}", salt.len()));

    Ok(result)
}

/// Convert bytes to hex string (avoids dependency on hex crate in non-dev builds).
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generate random bytes for salt using getrandom.
fn getrandom_salt() -> Result<Vec<u8>, JsError> {
    let mut bytes = vec![0u8; 62]; // 2 * 31 bytes (each < felt252 max)
    getrandom::getrandom(&mut bytes)
        .map_err(|e| JsError::new(&format!("Failed to generate random salt: {e}")))?;
    // Ensure each 31-byte chunk is < P (Stark prime) by clearing top bit
    bytes[0] &= 0x07; // first chunk high byte
    bytes[31] &= 0x07; // second chunk high byte
    Ok(bytes)
}

// ─── wasm-bindgen tests ──────────────────────────────────────────────────────
//
// Run with: wasm-pack test --node --features wasm
// These tests exercise the actual `#[wasm_bindgen]` surface through the
// wasm-bindgen-test harness (no browser required when using --node).

#[cfg(test)]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    // ── constants ───────────────────────────────────────────────────────────

    /// `public_key_length()` must return 896.
    #[wasm_bindgen_test]
    fn wasm_public_key_length_is_896() {
        assert_eq!(public_key_length(), 896);
    }

    /// `salt_length()` must return 40.
    #[wasm_bindgen_test]
    fn wasm_salt_length_is_40() {
        assert_eq!(salt_length(), 40);
    }

    // ── verify ──────────────────────────────────────────────────────────────

    /// `verify()` with wrong pk length returns an error.
    #[wasm_bindgen_test]
    fn wasm_verify_rejects_short_pk() {
        let short_pk = vec![0u8; 10];
        let result = verify(&short_pk, b"msg", b"sig");
        assert!(result.is_err(), "short pk must be rejected");
    }

    /// `verify()` with correct pk length but invalid signature is rejected.
    #[wasm_bindgen_test]
    fn wasm_verify_rejects_invalid_signature() {
        let zero_pk = vec![0u8; PUBLIC_KEY_LEN];
        let bad_sig = vec![0xFF_u8; 50]; // bad header
        let result = verify(&zero_pk, b"msg", &bad_sig);
        assert!(result.is_err(), "invalid signature header must be rejected");
    }

    // ── sign ────────────────────────────────────────────────────────────────

    /// `sign()` with invalid sk length (not 4 * PUBLIC_KEY_LEN) must return an error.
    #[wasm_bindgen_test]
    fn wasm_sign_rejects_invalid_sk_length() {
        let short_sk = vec![0u8; 100];
        let result = sign(&short_sk, b"hello", &[0u8; SALT_LEN]);
        assert!(result.is_err(), "sign() must reject sk with wrong length");
    }

    /// `sign()` with wrong salt length must return an error.
    #[wasm_bindgen_test]
    fn wasm_sign_rejects_invalid_salt_length() {
        // Use a dummy sk of the right byte length but invalid content
        let dummy_sk = vec![0u8; 4 * crate::falcon::PUBLIC_KEY_LEN];
        let wrong_salt = vec![0u8; 10]; // too short
        let result = sign(&dummy_sk, b"hello", &wrong_salt);
        assert!(result.is_err(), "sign() must reject salt with wrong length");
    }

    /// `sign()` with a valid sk (from keygen) must return a JS object with
    /// `signature` (Uint8Array of SIGNATURE_LEN) and `salt` (Uint8Array of SALT_LEN).
    ///
    /// NOTE: this test requires a real keypair, so it exercises the full keygen → sign path.
    /// Key generation is slow; this test is intentionally scoped to a fast deterministic path.
    #[wasm_bindgen_test]
    fn wasm_sign_succeeds_with_valid_sk() {
        use crate::falcon::SIGNATURE_LEN;

        let seed = [20u8; 32];
        let keypair = keygen(&seed).expect("keygen must succeed with 32-byte seed");

        // Extract sk bytes from the keypair JsValue
        let sk_js =
            js_sys::Reflect::get(&keypair, &"sk".into()).expect("keypair must have sk property");
        let sk_arr = js_sys::Uint8Array::from(sk_js);
        let sk_bytes = sk_arr.to_vec();

        let salt = [0u8; SALT_LEN];
        let result = sign(&sk_bytes, b"hello wasm sign", &salt);
        assert!(
            result.is_ok(),
            "sign() must succeed with valid sk: {:?}",
            result.err()
        );

        let result_obj = result.unwrap();

        // Must have a `signature` Uint8Array of length SIGNATURE_LEN
        let sig_js = js_sys::Reflect::get(&result_obj, &"signature".into())
            .expect("result must have `signature` property");
        let sig_arr = js_sys::Uint8Array::from(sig_js);
        assert_eq!(
            sig_arr.length() as usize,
            SIGNATURE_LEN,
            "signature must be SIGNATURE_LEN={} bytes",
            SIGNATURE_LEN
        );

        // Must have a `salt` Uint8Array of length SALT_LEN
        let salt_js = js_sys::Reflect::get(&result_obj, &"salt".into())
            .expect("result must have `salt` property");
        let salt_arr = js_sys::Uint8Array::from(salt_js);
        assert_eq!(
            salt_arr.length() as usize,
            SALT_LEN,
            "salt must be SALT_LEN={} bytes",
            SALT_LEN
        );

        // The embedded salt must match what we passed in
        let returned_salt = salt_arr.to_vec();
        assert_eq!(
            returned_salt,
            salt.to_vec(),
            "returned salt must match input salt"
        );
    }

    // ── create_verification_hint ──────────────────────────────────────

    #[wasm_bindgen_test]
    fn wasm_create_verification_hint_rejects_wrong_length() {
        let short = vec![0i32; 10];
        let correct = vec![0i32; 512];
        assert!(create_verification_hint(&short, &correct).is_err());
        assert!(create_verification_hint(&correct, &short).is_err());
    }

    // ── pack_public_key_wasm ────────────────────────────────────────────

    #[wasm_bindgen_test]
    fn wasm_pack_public_key_rejects_wrong_length() {
        let short = vec![0u16; 10];
        assert!(pack_public_key_wasm(&short).is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_pack_public_key_returns_29_slots() {
        let pk = vec![0u16; 512];
        let result = pack_public_key_wasm(&pk).expect("packing zeros must succeed");
        assert_eq!(result.len(), 29, "must produce exactly 29 felt252 slots");
        for slot in &result {
            assert!(slot.starts_with("0x"), "each slot must be 0x-prefixed hex");
        }
    }

    // ── sign + verify roundtrip ─────────────────────────────────────────

    /// `sign()` + `verify()` round-trip: a signature produced by `sign()` must
    /// pass `verify()` with the corresponding verifying key.
    #[wasm_bindgen_test]
    fn wasm_sign_verify_roundtrip() {
        let seed = [21u8; 32];
        let keypair = keygen(&seed).expect("keygen must succeed");

        let sk_js = js_sys::Reflect::get(&keypair, &"sk".into()).expect("keypair must have sk");
        let vk_js = js_sys::Reflect::get(&keypair, &"vk".into()).expect("keypair must have vk");

        let sk_bytes = js_sys::Uint8Array::from(sk_js).to_vec();
        let vk_bytes = js_sys::Uint8Array::from(vk_js).to_vec();

        let message = b"wasm sign-verify roundtrip";
        let salt = [1u8; SALT_LEN];

        let sign_result = sign(&sk_bytes, message, &salt).expect("sign must succeed with valid sk");

        // Extract the full signature bytes
        let sig_js = js_sys::Reflect::get(&sign_result, &"signature".into())
            .expect("sign result must have signature");
        let sig_bytes = js_sys::Uint8Array::from(sig_js).to_vec();

        let valid = verify(&vk_bytes, message, &sig_bytes)
            .expect("verify must not error on a valid signature");

        assert!(valid, "signature produced by sign() must verify with vk");
    }
}
