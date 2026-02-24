//! Generate test vectors for cross-language (Rust <-> Cairo) integration tests.
//!
//! Run with: cargo test generate_ -- --nocapture

use falcon_rs::falcon::Falcon;
use falcon_rs::hash_to_point::HashToPoint;
use falcon_rs::hints::generate_mul_hint;
use falcon_rs::ntt::ntt;
use falcon_rs::packing::{pack_public_key, unpack_public_key};
use falcon_rs::poseidon_hash::{Felt, PoseidonHashToPoint};
use falcon_rs::serialize;
use falcon_rs::{Q, SEED_LEN};
use std::fs;

#[test]
fn generate_hash_to_point_vector() {
    let message = vec![Felt::from(42u64)];
    let salt = vec![Felt::from(1u64), Felt::from(2u64)];
    let expected = PoseidonHashToPoint::hash_to_point(&message, &salt);
    let expected_u16: Vec<u16> = expected.iter().map(|&v| v as u16).collect();

    let json = serialize::hash_to_point_test_json(&message, &salt, &expected_u16);
    let path = "../s2morrow/packages/falcon/tests/data/hash_to_point_test_int.json";
    fs::write(path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
    println!("Wrote hash_to_point test vector to {path}");
}

#[test]
fn generate_packing_vector() {
    let values: Vec<u16> = (0..512).map(|i| ((i * 37) % 12289) as u16).collect();
    let packed = pack_public_key(&values);

    // Verify roundtrip in Rust first
    let unpacked = unpack_public_key(&packed);
    assert_eq!(unpacked, values, "Rust roundtrip failed");

    let json = serialize::packing_test_json(&values, &packed);
    let path = "../s2morrow/packages/falcon/tests/data/packing_test_int.json";
    fs::write(path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
    println!("Wrote packing test vector to {path}");
}

#[test]
fn generate_verify_vector() {
    // 1. Generate a deterministic keypair
    let seed = [42u8; 32];
    let (sk, vk) = Falcon::<PoseidonHashToPoint>::keygen_with_seed(&seed);

    // 2. Compute msg_point using Poseidon hash
    let message = vec![Felt::from(42u64)];
    let salt = vec![Felt::from(1u64), Felt::from(2u64)];
    let msg_point = PoseidonHashToPoint::hash_to_point(&message, &salt);

    // 3. Sign the prehashed point to get short (s0, s1)
    let sign_seed = [0u8; SEED_LEN];
    let (s0, s1) = Falcon::<PoseidonHashToPoint>::sign_prehashed(&sk, &msg_point, &sign_seed);

    // 4. Convert s1 to u16 via rem_euclid
    let s1_u16: Vec<u16> = s1.iter().map(|&v| v.rem_euclid(Q) as u16).collect();

    // 5. Compute pk_ntt = NTT(h) as u16
    let h_vec: Vec<i32> = vk.h().iter().copied().collect();
    let pk_ntt_i32 = ntt(&h_vec);
    let pk_ntt: Vec<u16> = pk_ntt_i32.iter().map(|&v| v.rem_euclid(Q) as u16).collect();

    // 6. Compute mul_hint = INTT(NTT(s1) * NTT(h))
    let mul_hint = generate_mul_hint(&s1_u16, &pk_ntt);

    // 7. Verify in Rust first: s0 + s1*h = msg_point (mod q)
    let s0_u16: Vec<u16> = s0.iter().map(|&v| v.rem_euclid(Q) as u16).collect();
    for i in 0..512 {
        let lhs = ((s0_u16[i] as i32 + mul_hint[i] as i32) % Q) as u16;
        assert_eq!(lhs, msg_point[i] as u16, "equation failed at index {i}");
    }

    // 8. Write JSON test vector
    let json = serialize::verify_test_json(&message, &salt, &pk_ntt, &s1_u16, &mul_hint);
    let path = "../s2morrow/packages/falcon/tests/data/verify_test_int.json";
    fs::write(path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
    println!("Wrote verify test vector to {path}");
    println!(
        "s1 norm check passed, pk_ntt len={}, mul_hint len={}",
        pk_ntt.len(),
        mul_hint.len()
    );
}
