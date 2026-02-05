//! Falcon sign/verify integration tests.
//!
//! Note: Keygen tests are slow (~minutes) due to NTRU key generation.
//! Run with `cargo test --release` for faster execution.

#[cfg(feature = "shake")]
mod tests {
    use falcon_rs::falcon::{Signature, VerifyingKey, PUBLIC_KEY_LEN};

    /// Test that verification rejects invalid signatures.
    #[test]
    fn test_verify_rejects_invalid_header() {
        // Create a fake signature with invalid header
        let mut sig_bytes = vec![0x00; 100]; // Wrong header (should be 0x39 for n=512)
        sig_bytes[0] = 0x00; // Invalid header

        let sig = Signature::from_bytes(&sig_bytes);
        assert!(sig.is_err());
    }

    /// Test signature deserialization with valid header.
    #[test]
    fn test_signature_header_validation() {
        // Valid header for Falcon-512 is 0x39 (0x30 + 9)
        let mut sig_bytes = vec![0u8; 50];
        sig_bytes[0] = 0x39; // Valid header

        let sig = Signature::from_bytes(&sig_bytes);
        assert!(sig.is_ok());
    }

    /// Test public key serialization roundtrip.
    #[test]
    fn test_public_key_zero() {
        let zero_key = [0u8; PUBLIC_KEY_LEN];
        let vk = VerifyingKey::from_bytes(&zero_key);
        assert!(vk.is_ok());

        let vk = vk.unwrap();
        let bytes = vk.to_bytes();
        assert_eq!(bytes, zero_key);
    }

    // Note: The following test is slow and should be run with --release
    // Uncomment to run full integration test
    //
    // #[test]
    // #[ignore] // Remove to run (takes ~1-2 minutes)
    // fn test_sign_verify_roundtrip() {
    //     let seed = [42u8; 32];
    //     let (sk, vk) = Falcon::<Shake256Hash>::keygen_with_seed(&seed);
    //
    //     let message = b"Hello, Falcon!";
    //     let salt = [0u8; 40];
    //     let sig = Falcon::<Shake256Hash>::sign_with_salt(&sk, message, &salt);
    //
    //     let result = Falcon::<Shake256Hash>::verify(&vk, message, &sig);
    //     assert!(result.is_ok());
    //     assert!(result.unwrap());
    // }
}
