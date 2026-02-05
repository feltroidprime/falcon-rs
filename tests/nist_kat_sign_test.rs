//! Test NIST KAT signing reproduction.
//!
//! NOTE: Full signature reproduction is NOT possible because falcon-rs
//! uses a different PRG than NIST. This test verifies:
//! - Secret keys can be parsed from NIST sk format
//! - Public keys can be reconstructed from NIST sk (f, g)
//! - Public keys match NIST format exactly
//! - NIST signatures verify with our reconstructed keys

#[cfg(feature = "shake")]
mod tests {
    use falcon_rs::nist_compat::{
        nist_to_falcon_signature, parse_nist_pk, parse_nist_sk, parse_nist_sm, serialize_nist_pk,
    };
    use falcon_rs::ntt::div_zq;
    use falcon_rs::N;
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct NistKatVector {
        count: u32,
        seed: String,
        mlen: usize,
        msg: String,
        pk: String,
        sk: String,
        smlen: usize,
        sm: String,
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        hex::decode(s).expect("invalid hex")
    }

    #[test]
    fn test_nist_sk_parsing() {
        let kat_json = include_str!("../test_vectors/nist_kat.json");
        let vectors: Vec<NistKatVector> =
            serde_json::from_str(kat_json).expect("failed to parse KAT JSON");

        // Test parsing first 10 vectors
        for v in vectors.iter().take(10) {
            let sk_bytes = hex_decode(&v.sk);

            let result = parse_nist_sk(&sk_bytes);
            assert!(
                result.is_ok(),
                "KAT {}: Failed to parse sk: {:?}",
                v.count,
                result.err()
            );

            let (f, g, f_upper) = result.unwrap();

            // Basic sanity checks - coefficients should be small
            for &coef in f.iter() {
                assert!(
                    coef.abs() < 64,
                    "KAT {}: f coefficient {} out of 6-bit range",
                    v.count,
                    coef
                );
            }
            for &coef in g.iter() {
                assert!(
                    coef.abs() < 64,
                    "KAT {}: g coefficient {} out of 6-bit range",
                    v.count,
                    coef
                );
            }
            for &coef in f_upper.iter() {
                assert!(
                    coef.abs() < 256,
                    "KAT {}: F coefficient {} out of 8-bit range",
                    v.count,
                    coef
                );
            }

            eprintln!("KAT {}: sk parsing PASS", v.count);
        }
    }

    #[test]
    fn test_nist_pk_reconstruction() {
        let kat_json = include_str!("../test_vectors/nist_kat.json");
        let vectors: Vec<NistKatVector> =
            serde_json::from_str(kat_json).expect("failed to parse KAT JSON");

        let mut passed = 0;
        let mut failed = 0;

        for v in vectors.iter().take(10) {
            let expected_pk = hex_decode(&v.pk);
            let sk_bytes = hex_decode(&v.sk);

            // Parse NIST secret key to get f, g, F
            let (f, g, _f_upper) = match parse_nist_sk(&sk_bytes) {
                Ok(result) => result,
                Err(e) => {
                    eprintln!("KAT {}: FAIL (sk parse: {:?})", v.count, e);
                    failed += 1;
                    continue;
                }
            };

            // Compute h = g/f mod (x^n + 1, q)
            let f_vec: Vec<i32> = f.iter().copied().collect();
            let g_vec: Vec<i32> = g.iter().copied().collect();

            let h_vec = match div_zq(&g_vec, &f_vec) {
                Some(h) => h,
                None => {
                    eprintln!("KAT {}: FAIL (f not invertible)", v.count);
                    failed += 1;
                    continue;
                }
            };

            let mut h = [0i32; N];
            h.copy_from_slice(&h_vec);

            // Serialize in NIST format
            let reconstructed_pk = serialize_nist_pk(&h);

            // Compare with expected
            if reconstructed_pk == expected_pk {
                eprintln!("KAT {}: pk reconstruction PASS", v.count);
                passed += 1;
            } else {
                eprintln!(
                    "KAT {}: FAIL (pk mismatch at byte {})",
                    v.count,
                    reconstructed_pk
                        .iter()
                        .zip(expected_pk.iter())
                        .position(|(a, b)| a != b)
                        .unwrap_or(reconstructed_pk.len().min(expected_pk.len()))
                );
                failed += 1;
            }
        }

        eprintln!(
            "\nPK Reconstruction Results: {} passed, {} failed",
            passed, failed
        );
        assert_eq!(failed, 0, "Some KAT vectors failed pk reconstruction");
    }

    #[test]
    fn test_nist_kat_sign_verify() {
        let kat_json = include_str!("../test_vectors/nist_kat.json");
        let vectors: Vec<NistKatVector> =
            serde_json::from_str(kat_json).expect("failed to parse KAT JSON");

        let mut passed = 0;
        let mut failed = 0;

        for v in vectors.iter().take(10) {
            let expected_pk = hex_decode(&v.pk);
            let expected_sk = hex_decode(&v.sk);
            let expected_sm = hex_decode(&v.sm);
            let msg = hex_decode(&v.msg);

            // Parse NIST secret key to get f, g, F
            let (_f, _g, _f_upper) = match parse_nist_sk(&expected_sk) {
                Ok(result) => result,
                Err(e) => {
                    eprintln!("KAT {}: FAIL (sk parse: {:?})", v.count, e);
                    failed += 1;
                    continue;
                }
            };

            // Parse the expected public key
            let vk = match parse_nist_pk(&expected_pk) {
                Ok(vk) => vk,
                Err(e) => {
                    eprintln!("KAT {}: FAIL (pk parse: {:?})", v.count, e);
                    failed += 1;
                    continue;
                }
            };

            // Parse NIST signed message
            let components = match parse_nist_sm(&expected_sm) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("KAT {}: FAIL (sm parse: {:?})", v.count, e);
                    failed += 1;
                    continue;
                }
            };

            // Verify extracted message matches
            if components.message != msg {
                eprintln!("KAT {}: FAIL (message mismatch)", v.count);
                failed += 1;
                continue;
            }

            // Create signature from NIST components and verify
            let sig = nist_to_falcon_signature(components.nonce, components.compressed_s1.clone());

            use falcon_rs::falcon::Falcon;
            use falcon_rs::hash_to_point::Shake256Hash;

            match Falcon::<Shake256Hash>::verify(&vk, &msg, &sig) {
                Ok(true) => {
                    eprintln!("KAT {}: PASS", v.count);
                    passed += 1;
                }
                Ok(false) => {
                    eprintln!("KAT {}: FAIL (verify returned false)", v.count);
                    failed += 1;
                }
                Err(e) => {
                    eprintln!("KAT {}: FAIL (verify error: {:?})", v.count, e);
                    failed += 1;
                }
            }
        }

        eprintln!("\nResults: {} passed, {} failed", passed, failed);
        assert_eq!(failed, 0);
    }
}
