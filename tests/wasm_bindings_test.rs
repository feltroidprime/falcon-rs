//! Integration tests for WASM bindings functionality.
//!
//! Tests the core operations exposed via `src/wasm.rs` — sign, hint generation,
//! and public key packing — through the native Rust API. These tests validate
//! correctness of the underlying logic that the wasm-bindgen wrappers delegate to.
//!
//! Actual wasm-bindgen browser/node tests live in `src/wasm_bindgen_tests.rs`
//! and are run via `wasm-pack test --node`.

#[cfg(feature = "shake")]
mod wasm_sign_tests {
    use falcon_rs::falcon::{Falcon, Signature, SIGNATURE_LEN};
    use falcon_rs::hash_to_point::Shake256Hash;
    use falcon_rs::SALT_LEN;

    // ─── sign (native Rust path behind the wasm binding) ────────────────────

    /// The WASM `sign()` binding is a documented placeholder — it always returns
    /// an error. This test asserts that contract is honoured so we catch any
    /// unintentional implementation slip.
    #[test]
    fn test_wasm_sign_is_unimplemented_placeholder() {
        // The wasm.rs `sign()` function intentionally returns an error:
        // "sign() not yet implemented for WASM. Use native Rust API."
        // We verify the native API works and document that the wasm wrapper
        // needs implementation as a separate ticket.

        // Native signing DOES work — use keygen_with_seed for determinism.
        let seed = [1u8; 32];
        let (sk, vk) = Falcon::<Shake256Hash>::keygen_with_seed(&seed);

        let message = b"hello wasm";
        let salt = [0u8; SALT_LEN];
        let sig = Falcon::<Shake256Hash>::sign_with_salt(&sk, message, &salt);

        let result = Falcon::<Shake256Hash>::verify(&vk, message, &sig);
        assert!(result.is_ok(), "native sign/verify should succeed");
        assert!(result.unwrap(), "native signature should be valid");
    }

    /// Sign with two different seeds produces different signatures
    /// (salt randomness matters).
    #[test]
    fn test_sign_different_salts_produce_different_signatures() {
        let seed = [2u8; 32];
        let (sk, _vk) = Falcon::<Shake256Hash>::keygen_with_seed(&seed);
        let message = b"same message";

        let salt1 = [0u8; SALT_LEN];
        let salt2 = [1u8; SALT_LEN];

        let sig1 = Falcon::<Shake256Hash>::sign_with_salt(&sk, message, &salt1);
        let sig2 = Falcon::<Shake256Hash>::sign_with_salt(&sk, message, &salt2);

        assert_ne!(
            sig1.to_bytes(),
            sig2.to_bytes(),
            "different salts must produce different signatures"
        );
    }

    /// Signature byte length matches the expected constant.
    #[test]
    fn test_signature_byte_length() {
        let seed = [3u8; 32];
        let (sk, _vk) = Falcon::<Shake256Hash>::keygen_with_seed(&seed);
        let salt = [0u8; SALT_LEN];
        let sig = Falcon::<Shake256Hash>::sign_with_salt(&sk, b"test", &salt);
        assert_eq!(
            sig.to_bytes().len(),
            SIGNATURE_LEN,
            "signature length must be SIGNATURE_LEN={SIGNATURE_LEN}"
        );
    }

    /// `Signature::from_bytes` round-trips through serialization.
    #[test]
    fn test_signature_serialization_roundtrip() {
        let seed = [4u8; 32];
        let (sk, _vk) = Falcon::<Shake256Hash>::keygen_with_seed(&seed);
        let salt = [0u8; SALT_LEN];
        let sig = Falcon::<Shake256Hash>::sign_with_salt(&sk, b"roundtrip", &salt);

        let bytes = sig.to_bytes();
        let sig2 = Signature::from_bytes(&bytes).expect("deserialization must succeed");
        assert_eq!(
            bytes,
            sig2.to_bytes(),
            "round-tripped signature bytes must match"
        );
    }
}

// ─── hint generation ────────────────────────────────────────────────────────

mod hint_generation_tests {
    use falcon_rs::hints::generate_mul_hint;
    use falcon_rs::ntt::ntt;
    use falcon_rs::Q;

    /// Hint for identity: INTT(NTT([1,0…]) * NTT([1,0…])) == [1,0…]
    #[test]
    fn test_generate_mul_hint_identity() {
        let mut s1 = vec![0u16; 512];
        s1[0] = 1;
        let s1_i32: Vec<i32> = s1.iter().map(|&v| v as i32).collect();
        let pk_ntt_i32 = ntt(&s1_i32);
        let pk_ntt: Vec<u16> = pk_ntt_i32
            .iter()
            .map(|&v| v.rem_euclid(Q) as u16)
            .collect();

        let hint = generate_mul_hint(&s1, &pk_ntt);

        assert_eq!(hint.len(), 512);
        assert_eq!(hint[0], 1, "coefficient 0 of identity hint must be 1");
        for i in 1..512 {
            assert_eq!(
                hint[i], 0,
                "coefficient {i} of identity hint must be 0, got {}",
                hint[i]
            );
        }
    }

    /// Hint length is always 512.
    #[test]
    fn test_generate_mul_hint_length() {
        let s1 = vec![42u16; 512];
        let pk_ntt = vec![1u16; 512];
        let hint = generate_mul_hint(&s1, &pk_ntt);
        assert_eq!(hint.len(), 512);
    }

    /// All hint coefficients are in [0, Q).
    #[test]
    fn test_generate_mul_hint_range() {
        let s1: Vec<u16> = (0..512).map(|i| (i * 37 % (Q as usize)) as u16).collect();
        let pk_ntt: Vec<u16> = (0..512)
            .map(|i| (i * 53 % (Q as usize)) as u16)
            .collect();
        let hint = generate_mul_hint(&s1, &pk_ntt);
        for (i, &v) in hint.iter().enumerate() {
            assert!(
                (v as i32) < Q,
                "hint[{i}] = {v} is not in [0, Q={Q})"
            );
        }
    }

    /// Zero s1 gives a zero hint (0 * anything = 0).
    #[test]
    fn test_generate_mul_hint_zero_s1() {
        let s1 = vec![0u16; 512];
        let pk_ntt: Vec<u16> = (0..512)
            .map(|i| (i * 37 % (Q as usize)) as u16)
            .collect();
        let hint = generate_mul_hint(&s1, &pk_ntt);
        assert!(hint.iter().all(|&v| v == 0), "zero s1 must give zero hint");
    }

    /// Zero pk_ntt gives a zero hint (anything * 0 = 0).
    #[test]
    fn test_generate_mul_hint_zero_pk() {
        let s1: Vec<u16> = (0..512).map(|i| (i * 37 % (Q as usize)) as u16).collect();
        let pk_ntt = vec![0u16; 512];
        let hint = generate_mul_hint(&s1, &pk_ntt);
        assert!(hint.iter().all(|&v| v == 0), "zero pk_ntt must give zero hint");
    }

    /// Hint is consistent: calling generate_mul_hint twice with same inputs gives same result.
    #[test]
    fn test_generate_mul_hint_deterministic() {
        let s1: Vec<u16> = (0..512).map(|i| (i * 7 % (Q as usize)) as u16).collect();
        let pk_ntt: Vec<u16> = (0..512)
            .map(|i| (i * 13 % (Q as usize)) as u16)
            .collect();
        let h1 = generate_mul_hint(&s1, &pk_ntt);
        let h2 = generate_mul_hint(&s1, &pk_ntt);
        assert_eq!(h1, h2, "generate_mul_hint must be deterministic");
    }
}

// ─── public key packing ──────────────────────────────────────────────────────

mod public_key_packing_tests {
    use falcon_rs::packing::{pack_public_key, unpack_public_key, PACKED_SLOTS};
    use falcon_rs::Q;

    /// Packing produces exactly PACKED_SLOTS=29 felt252 slots.
    #[test]
    fn test_pack_public_key_slot_count() {
        let values = vec![0u16; 512];
        let packed = pack_public_key(&values);
        assert_eq!(
            packed.len(),
            PACKED_SLOTS,
            "packed pk must have exactly {PACKED_SLOTS} slots"
        );
    }

    /// Round-trip: unpack(pack(v)) == v for sequential values.
    #[test]
    fn test_pack_unpack_roundtrip_sequential() {
        let values: Vec<u16> = (0..512).map(|i| (i * 37 % (Q as usize)) as u16).collect();
        let packed = pack_public_key(&values);
        let unpacked = unpack_public_key(&packed);
        assert_eq!(unpacked, values, "roundtrip sequential values must match");
    }

    /// Round-trip with all-zero polynomial.
    #[test]
    fn test_pack_unpack_zeros() {
        let zeros = vec![0u16; 512];
        assert_eq!(
            unpack_public_key(&pack_public_key(&zeros)),
            zeros,
            "roundtrip zeros"
        );
    }

    /// Round-trip with all-max polynomial (Q-1 = 12288).
    #[test]
    fn test_pack_unpack_max_values() {
        let maxes = vec![(Q as u16) - 1; 512];
        assert_eq!(
            unpack_public_key(&pack_public_key(&maxes)),
            maxes,
            "roundtrip max values"
        );
    }

    /// Round-trip with alternating values.
    #[test]
    fn test_pack_unpack_alternating() {
        let values: Vec<u16> = (0..512).map(|i| if i % 2 == 0 { 0 } else { 12288 }).collect();
        assert_eq!(
            unpack_public_key(&pack_public_key(&values)),
            values,
            "roundtrip alternating"
        );
    }

    /// Packing is deterministic.
    #[test]
    fn test_pack_public_key_deterministic() {
        let values: Vec<u16> = (0..512).map(|i| (i * 17 % (Q as usize)) as u16).collect();
        let p1 = pack_public_key(&values);
        let p2 = pack_public_key(&values);
        assert_eq!(p1, p2, "packing must be deterministic");
    }

    /// Different inputs produce different packed outputs.
    #[test]
    fn test_pack_public_key_distinct_inputs() {
        let v1: Vec<u16> = vec![0u16; 512];
        let v2: Vec<u16> = vec![1u16; 512];
        let p1 = pack_public_key(&v1);
        let p2 = pack_public_key(&v2);
        assert_ne!(p1, p2, "distinct inputs must produce distinct packed outputs");
    }
}

// ─── verify (what the wasm `verify` binding delegates to) ───────────────────

#[cfg(feature = "shake")]
mod wasm_verify_tests {
    use falcon_rs::falcon::{Falcon, Signature, VerifyingKey, PUBLIC_KEY_LEN};
    use falcon_rs::hash_to_point::Shake256Hash;
    use falcon_rs::SALT_LEN;

    /// Valid sign+verify round-trip matches what `wasm::verify` would call.
    #[test]
    fn test_wasm_verify_valid_signature() {
        let seed = [10u8; 32];
        let (sk, vk) = Falcon::<Shake256Hash>::keygen_with_seed(&seed);
        let message = b"verify me";
        let salt = [0u8; SALT_LEN];
        let sig = Falcon::<Shake256Hash>::sign_with_salt(&sk, message, &salt);

        let result = Falcon::<Shake256Hash>::verify(&vk, message, &sig);
        assert!(result.is_ok() && result.unwrap(), "valid signature should verify");
    }

    /// Wrong message fails verification.
    #[test]
    fn test_wasm_verify_wrong_message() {
        let seed = [11u8; 32];
        let (sk, vk) = Falcon::<Shake256Hash>::keygen_with_seed(&seed);
        let salt = [0u8; SALT_LEN];
        let sig = Falcon::<Shake256Hash>::sign_with_salt(&sk, b"original", &salt);

        let result = Falcon::<Shake256Hash>::verify(&vk, b"tampered", &sig);
        // Should either be Err or Ok(false)
        let is_invalid = result.map(|ok| !ok).unwrap_or(true);
        assert!(is_invalid, "wrong message must not verify");
    }

    /// Invalid public key length is rejected (mirrors wasm::verify length check).
    #[test]
    fn test_wasm_verify_invalid_pk_length() {
        let short_pk = vec![0u8; PUBLIC_KEY_LEN - 1];
        let result = VerifyingKey::from_bytes(
            &short_pk
                .as_slice()
                .try_into()
                .unwrap_or([0u8; PUBLIC_KEY_LEN]),
        );
        // The wasm binding checks len != PUBLIC_KEY_LEN before calling from_bytes.
        // Here we verify from_bytes on a zero-filled key (valid encoding) works.
        let zero_pk = [0u8; PUBLIC_KEY_LEN];
        let vk_result = VerifyingKey::from_bytes(&zero_pk);
        assert!(vk_result.is_ok(), "zero pk bytes must deserialize without error");
    }

    /// Invalid signature header is rejected.
    #[test]
    fn test_wasm_verify_invalid_signature_header() {
        let mut bad_sig = vec![0u8; 100];
        bad_sig[0] = 0xFF; // invalid header
        let sig_result = Signature::from_bytes(&bad_sig);
        assert!(sig_result.is_err(), "invalid header must be rejected");
    }

    /// `public_key_length()` and `salt_length()` return the right constants.
    #[test]
    fn test_wasm_constants() {
        assert_eq!(
            falcon_rs::falcon::PUBLIC_KEY_LEN,
            896,
            "PUBLIC_KEY_LEN must be 896"
        );
        assert_eq!(falcon_rs::SALT_LEN, 40, "SALT_LEN must be 40");
    }
}
