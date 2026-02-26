/// Test to compare msg_point between Rust and Cairo for specific deploy inputs
use falcon_rs::poseidon_hash::{Felt, PoseidonHashToPoint};
use falcon_rs::hash_to_point::HashToPoint;

fn felt_to_decimal(f: &Felt) -> String {
    let bytes = f.to_bytes_be();
    let big = num_bigint::BigUint::from_bytes_be(&bytes);
    big.to_string()
}

fn felt_from_decimal(dec: &str) -> Felt {
    let big: num_bigint::BigUint = dec.parse().unwrap();
    let hex = format!("0x{}", big.to_str_radix(16));
    Felt::from_hex(&hex).unwrap()
}

#[test]
fn test_msg_point_matches_cairo() {
    // Values from the actual deploy attempt
    let tx_hash_hex = "0x56426e23baae2bb2b72b9a6c94ef5f40dddc4eac8069c4d1a1904f8414092e0";
    let salt0_dec = "9000997443405655305309449961417703029127379031181025947003219145455995761";
    let salt1_dec = "3524459295862428748210246636424043243932833293804227548985638395763187338";

    let tx_hash_felt = Felt::from_hex(tx_hash_hex).unwrap();
    let salt0_felt = felt_from_decimal(salt0_dec);
    let salt1_felt = felt_from_decimal(salt1_dec);

    println!("tx_hash decimal: {}", felt_to_decimal(&tx_hash_felt));
    println!("salt[0] decimal: {}", felt_to_decimal(&salt0_felt));
    println!("salt[1] decimal: {}", felt_to_decimal(&salt1_felt));

    let message = vec![tx_hash_felt];
    let salt = vec![salt0_felt, salt1_felt];

    let msg_point = PoseidonHashToPoint::hash_to_point(&message, &salt);

    println!("msg_point[0] = {}", msg_point[0]); // Cairo shows 4127
    println!("msg_point[1] = {}", msg_point[1]); // Cairo shows 9859
    println!("msg_point len = {}", msg_point.len());

    // Cairo output: msg_point[0]=4127, msg_point[1]=9859
    assert_eq!(msg_point[0], 4127, "msg_point[0] should match Cairo");
    assert_eq!(msg_point[1], 9859, "msg_point[1] should match Cairo");
}
