//! Integration tests for SecretKey::from_bytes reconstruction.

#[cfg(feature = "shake")]
mod tests {
    use falcon_rs::falcon::{Falcon, FalconError, SecretKey, PUBLIC_KEY_LEN};
    use falcon_rs::hash_to_point::Shake256Hash;
    use falcon_rs::SALT_LEN;

    #[test]
    fn test_secret_key_from_bytes_roundtrip_sign_verify() {
        let seed = [42u8; 32];
        let (sk, vk) = Falcon::<Shake256Hash>::keygen_with_seed(&seed);
        let sk2 = SecretKey::from_bytes(&sk.to_bytes()).expect("from_bytes should succeed");

        let message = b"integration roundtrip";
        let salt = [7u8; SALT_LEN];
        let sig = Falcon::<Shake256Hash>::sign_with_salt(&sk2, message, &salt);

        let result = Falcon::<Shake256Hash>::verify(&vk, message, &sig);
        assert!(result.is_ok(), "verification should not error");
        assert!(result.unwrap(), "signature should verify");
    }

    #[test]
    fn test_secret_key_from_bytes_rejects_wrong_length() {
        assert!(
            matches!(
                SecretKey::from_bytes(&[]),
                Err(FalconError::InvalidSecretKey)
            ),
            "empty byte slice should fail",
        );

        let short = vec![0u8; PUBLIC_KEY_LEN];
        assert!(
            matches!(
                SecretKey::from_bytes(&short),
                Err(FalconError::InvalidSecretKey)
            ),
            "single polynomial length should fail",
        );
    }

    #[test]
    fn test_secret_key_from_bytes_rejects_invalid_encoded_coeff() {
        let mut bytes = vec![0u8; 4 * PUBLIC_KEY_LEN];
        bytes[0] = 0x01;
        bytes[1] = 0x30;

        assert!(
            matches!(
                SecretKey::from_bytes(&bytes),
                Err(FalconError::InvalidSecretKey)
            ),
            "invalid encoded coefficient should fail",
        );
    }
}
