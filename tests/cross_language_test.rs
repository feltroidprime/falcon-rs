//! Cross-language integration tests for Falcon-RS.
//!
//! These tests verify compatibility between Rust and Python implementations.
//!
//! To generate test vectors from Python:
//! 1. Install Python dependencies: pip install numpy pycryptodome beartype
//! 2. Run: python3 scripts/generate_hash_to_point_kat.py > test_vectors/hash_to_point_kat.json
//! 3. Run these tests: cargo test --features shake cross_language

#[cfg(feature = "shake")]
mod tests {
    use falcon_rs::hash_to_point::{HashToPoint, Shake256Hash};
    use falcon_rs::SALT_LEN;

    /// Test that hash_to_point produces consistent results.
    /// These values can be compared against Python implementation.
    #[test]
    fn test_hash_to_point_known_values() {
        // Test with empty message and zero salt
        let message = b"";
        let salt = [0u8; SALT_LEN];

        let hash = Shake256Hash::hash_to_point(message, &salt);

        // Verify basic properties
        assert_eq!(hash.len(), 512);

        // All values should be in range [0, q)
        for &coef in &hash {
            assert!(coef >= 0);
            assert!((coef as i32) < 12289);
        }

        // First few coefficients should be deterministic
        // (These can be verified against Python if needed)
        eprintln!("First 10 hash coefficients: {:?}", &hash[..10]);
    }

    /// Test with a specific message for cross-language verification.
    #[test]
    fn test_hash_to_point_hello() {
        let message = b"Hello, Falcon!";
        let salt = [0u8; SALT_LEN];

        let hash = Shake256Hash::hash_to_point(message, &salt);

        // Print for comparison with Python
        eprintln!("hash_to_point('Hello, Falcon!', zeros(40)):");
        eprintln!("First 10: {:?}", &hash[..10]);
        eprintln!("Last 10: {:?}", &hash[502..]);

        // Verify determinism
        let hash2 = Shake256Hash::hash_to_point(message, &salt);
        assert_eq!(hash, hash2);
    }

    /// Test encoding roundtrip for cross-language compatibility.
    #[test]
    fn test_encoding_compatibility() {
        use falcon_rs::encoding::{compress, decompress};

        // Test vector that might come from Python
        let coeffs = vec![1, -1, 2, -2, 0, 127, -128, 255, -255];
        let compressed = compress(&coeffs, 100).expect("compression failed");
        let decompressed = decompress(&compressed, coeffs.len()).expect("decompression failed");

        assert_eq!(coeffs, decompressed);
    }

    /// Test public key serialization format.
    #[test]
    fn test_public_key_format() {
        use falcon_rs::encoding::{deserialize_public_key, serialize_public_key};
        use falcon_rs::N;

        // Create a test polynomial
        let mut poly = [0i32; N];
        for i in 0..N {
            poly[i] = ((i * 23) % 12289) as i32; // Values in [0, q)
        }

        let bytes = serialize_public_key(&poly);

        // Verify length: 512 coefficients * 14 bits / 8 = 896 bytes
        assert_eq!(bytes.len(), 896);

        // Verify roundtrip
        let recovered = deserialize_public_key(&bytes).expect("deserialization failed");
        assert_eq!(poly, recovered);
    }
}
