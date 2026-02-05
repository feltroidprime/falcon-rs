//! Test Falcon verification against NIST KAT vectors.

#[cfg(feature = "shake")]
mod tests {
    use falcon_rs::falcon::Falcon;
    use falcon_rs::hash_to_point::Shake256Hash;
    use falcon_rs::nist_compat::{nist_to_falcon_signature, parse_nist_pk, parse_nist_sm};
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
    fn test_nist_kat_verify() {
        let kat_json = include_str!("../test_vectors/nist_kat.json");
        let vectors: Vec<NistKatVector> =
            serde_json::from_str(kat_json).expect("failed to parse KAT JSON");

        let mut passed = 0;
        let mut failed = 0;

        for v in &vectors {
            let pk = hex_decode(&v.pk);
            let msg = hex_decode(&v.msg);
            let sm = hex_decode(&v.sm);

            // Parse NIST format
            let components = match parse_nist_sm(&sm) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("KAT {}: FAIL (sm parse error: {:?})", v.count, e);
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

            // Parse public key (uses big-endian deserializer)
            let vk = match parse_nist_pk(&pk) {
                Ok(vk) => vk,
                Err(e) => {
                    eprintln!("KAT {}: FAIL (pk parse error: {:?})", v.count, e);
                    failed += 1;
                    continue;
                }
            };

            // Convert to falcon-rs format and verify
            let sig = nist_to_falcon_signature(components.nonce, components.compressed_s1);

            match Falcon::<Shake256Hash>::verify(&vk, &msg, &sig) {
                Ok(true) => {
                    eprintln!("KAT {}: PASS", v.count);
                    passed += 1;
                }
                Ok(false) => {
                    eprintln!("KAT {}: FAIL (verification returned false)", v.count);
                    failed += 1;
                }
                Err(e) => {
                    eprintln!("KAT {}: FAIL (verification error: {:?})", v.count, e);
                    failed += 1;
                }
            }
        }

        eprintln!("\nResults: {} passed, {} failed", passed, failed);
        assert_eq!(failed, 0, "Some KAT vectors failed verification");
    }
}
