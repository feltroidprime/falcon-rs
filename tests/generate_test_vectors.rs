//! Generate test vectors for cross-language (Rust <-> Cairo) integration tests.
//!
//! Run with: cargo test generate_ -- --nocapture

use falcon_rs::poseidon_hash::{Felt, PoseidonHashToPoint};
use falcon_rs::packing::{pack_public_key, unpack_public_key};
use falcon_rs::serialize;
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
