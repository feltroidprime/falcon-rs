//! Integration test: exercises the exact same code path as the
//! `sign_for_starknet` WASM function, then verifies the result
//! using the on-chain verification logic (NTT checks + norm bound).
//!
//! Does NOT use the `wasm` feature or `wasm_bindgen`.

use falcon_rs::common::sqnorm;
use falcon_rs::falcon::{Falcon, VerifyingKey};
use falcon_rs::hash_to_point::HashToPoint;
use falcon_rs::hints::generate_mul_hint;
use falcon_rs::ntt::{mul_ntt, ntt};
use falcon_rs::packing::{pack_public_key, unpack_public_key};
use falcon_rs::poseidon_hash::{Felt, PoseidonHashToPoint};
use falcon_rs::{N, Q, SALT_LEN, SEED_LEN};

/// Signature bound from the Falcon-512 spec: ||(s0, s1)||^2 <= 34034726
const SIG_BOUND: i64 = 34034726;

/// Helper: convert Felt to canonical hex string (same logic as wasm.rs felt_to_hex).
fn felt_to_hex(f: &Felt) -> String {
    let bytes = f.to_bytes_be();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let stripped = hex.trim_start_matches('0');
    if stripped.is_empty() {
        "0".to_string()
    } else {
        stripped.to_string()
    }
}

#[test]
fn test_sign_for_starknet() {
    println!("\n=== test_sign_for_starknet ===\n");

    // ── Step 1: Generate keypair with fixed seed (bytes 1..32, same as CLI) ──
    let seed: Vec<u8> = (1u8..=32).collect();
    println!("[1] Generating keypair with seed 1..32 (this takes ~1 min in debug)...");
    let (sk, vk) = Falcon::<PoseidonHashToPoint>::keygen_with_seed(&seed);
    println!("    Keypair generated.");

    // ── Step 2: Parse VK bytes -> pk_ntt (512 NTT-domain coefficients) ──
    let vk_bytes = vk.to_bytes();
    println!(
        "[2] VK bytes length: {} (expected {})",
        vk_bytes.len(),
        falcon_rs::falcon::PUBLIC_KEY_LEN
    );
    let vk_restored = VerifyingKey::from_bytes(
        &vk_bytes
            .as_slice()
            .try_into()
            .expect("VK bytes wrong length"),
    )
    .expect("VK deserialization failed");
    let h_coeffs: Vec<i32> = vk_restored.h().to_vec();
    let pk_ntt: Vec<i32> = ntt(&h_coeffs);
    println!(
        "    pk_ntt[0..5] = {:?}",
        &pk_ntt[..5]
    );

    // ── Step 3: Pick a sample tx_hash ──
    let tx_hash_hex = "0x3ddc9b02a6167e35008d46c8a9460bdaeca8a191dcdcd7207621d4b8d14f54b";
    let tx_hash_felt = Felt::from_hex(tx_hash_hex).expect("Invalid tx_hash hex");
    println!("[3] tx_hash = {tx_hash_hex}");

    // ── Step 4: Replicate sign_for_starknet logic ──

    // 4a. Generate a deterministic salt (fixed for reproducibility)
    //     Use 62 bytes like the WASM function, clear top bits of each 31-byte chunk.
    let mut salt_bytes = vec![0u8; 62];
    for i in 0..62 {
        salt_bytes[i] = ((i as u8).wrapping_mul(7)).wrapping_add(13);
    }
    salt_bytes[0] &= 0x07; // first chunk high byte
    salt_bytes[31] &= 0x07; // second chunk high byte

    let salt_hex0 = salt_bytes[..31]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let salt_hex1 = salt_bytes[31..62]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let salt_felt0 =
        Felt::from_hex(&format!("0x{salt_hex0}")).expect("Failed to create salt felt 0");
    let salt_felt1 =
        Felt::from_hex(&format!("0x{salt_hex1}")).expect("Failed to create salt felt 1");
    let salt = vec![salt_felt0, salt_felt1];
    println!("[4a] salt_felt0 = 0x{}", felt_to_hex(&salt_felt0));
    println!("     salt_felt1 = 0x{}", felt_to_hex(&salt_felt1));

    // 4b. Compute msg_point = PoseidonHashToPoint([tx_hash], salt)
    let message = vec![tx_hash_felt];
    let msg_point = PoseidonHashToPoint::hash_to_point(&message, &salt);
    println!(
        "[4b] msg_point[0..5] = {:?}",
        &msg_point[..5]
    );
    // Verify range
    for (i, &v) in msg_point.iter().enumerate() {
        assert!(
            v >= 0 && (v as i32) < Q,
            "msg_point[{i}] = {v} out of range [0, Q)"
        );
    }

    // 4c. Sign via sign_prehashed (same as WASM)
    let sign_seed = {
        let mut s = [0u8; SEED_LEN];
        s[..SALT_LEN].copy_from_slice(&salt_bytes[..SALT_LEN]);
        s
    };
    println!("[4c] Signing prehashed message...");
    let (_s0_raw, s1_raw) =
        Falcon::<PoseidonHashToPoint>::sign_prehashed(&sk, &msg_point, &sign_seed);
    println!(
        "     s1_raw[0..5] = {:?}",
        &s1_raw[..5]
    );

    // 4d. Convert s1 to u16 (unsigned mod Q) — same as wasm.rs line 255
    let s1_u16: Vec<u16> = s1_raw
        .iter()
        .map(|&v| v.rem_euclid(Q) as u16)
        .collect();
    println!(
        "[4d] s1_u16[0..5] = {:?}",
        &s1_u16[..5]
    );

    // 4e. Convert pk_ntt to u16
    let pk_u16: Vec<u16> = pk_ntt
        .iter()
        .map(|&v| v.rem_euclid(Q) as u16)
        .collect();

    // 4f. Compute mul_hint = INTT(NTT(s1) * pk_ntt)
    let mul_hint = generate_mul_hint(&s1_u16, &pk_u16);
    println!(
        "[4f] mul_hint[0..5] = {:?}",
        &mul_hint[..5]
    );

    // 4g. Pack s1 and mul_hint into 29 felt252 each
    let packed_s1 = pack_public_key(&s1_u16);
    let packed_hint = pack_public_key(&mul_hint);
    assert_eq!(packed_s1.len(), 29);
    assert_eq!(packed_hint.len(), 29);
    println!("[4g] packed_s1[0] = 0x{}", felt_to_hex(&packed_s1[0]));
    println!("     packed_hint[0] = 0x{}", felt_to_hex(&packed_hint[0]));

    // 4h. Build the 61-element output (same order as WASM)
    let mut result_felts: Vec<String> = Vec::with_capacity(61);
    for f in &packed_s1 {
        result_felts.push(format!("0x{}", felt_to_hex(f)));
    }
    result_felts.push(format!("0x{:x}", salt.len())); // salt array length
    for f in &salt {
        result_felts.push(format!("0x{}", felt_to_hex(f)));
    }
    for f in &packed_hint {
        result_felts.push(format!("0x{}", felt_to_hex(f)));
    }
    assert_eq!(result_felts.len(), 61, "Expected 61 felt252 elements");
    println!("[4h] Output: {} felt252 elements", result_felts.len());
    println!("     First 3: {:?}", &result_felts[..3]);
    println!("     Salt segment: {:?}", &result_felts[29..32]);

    // ══════════════════════════════════════════════════════════════════════
    // ── Step 5: VERIFY the result ──
    // ══════════════════════════════════════════════════════════════════════
    println!("\n--- VERIFICATION ---\n");

    // 5a. Unpack s1 and mul_hint back from packed form
    let s1_unpacked = unpack_public_key(&packed_s1);
    let hint_unpacked = unpack_public_key(&packed_hint);
    assert_eq!(s1_unpacked.len(), 512);
    assert_eq!(hint_unpacked.len(), 512);
    assert_eq!(s1_unpacked, s1_u16, "s1 pack/unpack roundtrip failed");
    assert_eq!(
        hint_unpacked, mul_hint,
        "mul_hint pack/unpack roundtrip failed"
    );
    println!("[5a] Pack/unpack roundtrip OK for s1 and mul_hint");

    // 5b. Compute NTT(s1) and NTT(mul_hint)
    let s1_i32: Vec<i32> = s1_unpacked.iter().map(|&v| v as i32).collect();
    let hint_i32: Vec<i32> = hint_unpacked.iter().map(|&v| v as i32).collect();
    let s1_ntt = ntt(&s1_i32);
    let hint_ntt = ntt(&hint_i32);
    println!(
        "[5b] NTT(s1)[0..3] = {:?}",
        &s1_ntt[..3]
    );
    println!(
        "     NTT(hint)[0..3] = {:?}",
        &hint_ntt[..3]
    );

    // 5c. Check NTT(s1) * pk_ntt == NTT(mul_hint) pointwise (mod Q)
    //     This is the core Cairo on-chain check.
    let product_ntt = mul_ntt(&s1_ntt, &pk_ntt);
    let mut ntt_mismatch_count = 0;
    for i in 0..N {
        let expected = hint_ntt[i].rem_euclid(Q);
        let actual = product_ntt[i].rem_euclid(Q);
        if expected != actual {
            if ntt_mismatch_count < 5 {
                println!(
                    "     MISMATCH at [{i}]: NTT(s1)*pk_ntt = {actual}, NTT(hint) = {expected}"
                );
            }
            ntt_mismatch_count += 1;
        }
    }
    assert_eq!(
        ntt_mismatch_count, 0,
        "NTT(s1) * pk_ntt != NTT(mul_hint) at {ntt_mismatch_count} positions"
    );
    println!("[5c] NTT(s1) * pk_ntt == NTT(mul_hint) -- PASS (all 512 positions match)");

    // 5d. Compute s0 = msg_point - mul_hint (mod Q), then center to [-Q/2, Q/2]
    let msg_i32: Vec<i32> = msg_point.iter().map(|&v| v as i32).collect();
    let s0_centered: Vec<i32> = msg_i32
        .iter()
        .zip(hint_i32.iter())
        .map(|(&m, &h)| {
            let diff = (m - h).rem_euclid(Q);
            if diff > Q / 2 {
                diff - Q
            } else {
                diff
            }
        })
        .collect();

    // s1 must also be centered for the norm check
    let s1_centered: Vec<i32> = s1_i32
        .iter()
        .map(|&v| {
            let c = v.rem_euclid(Q);
            if c > Q / 2 {
                c - Q
            } else {
                c
            }
        })
        .collect();

    println!(
        "[5d] s0_centered[0..5] = {:?}",
        &s0_centered[..5]
    );
    println!(
        "     s1_centered[0..5] = {:?}",
        &s1_centered[..5]
    );

    // 5e. Check ||(s0, s1)||^2 <= SIG_BOUND
    let norm = sqnorm(&[s0_centered.as_slice(), s1_centered.as_slice()]);
    println!("[5e] ||(s0, s1)||^2 = {norm}");
    println!("     SIG_BOUND      = {SIG_BOUND}");
    println!(
        "     norm <= bound?  {}",
        if norm <= SIG_BOUND { "PASS" } else { "FAIL" }
    );
    assert!(
        norm <= SIG_BOUND,
        "Signature norm {norm} exceeds bound {SIG_BOUND}"
    );

    // ── Cross-check: s0 + s1*h == msg_point (mod Q) ──
    // This is the fundamental Falcon identity. If the hint check passed AND
    // this holds, the signature is fully valid.
    let s1_times_h = falcon_rs::ntt::mul_zq(&s1_centered, &h_coeffs);
    let reconstructed: Vec<i32> = s0_centered
        .iter()
        .zip(s1_times_h.iter())
        .map(|(&s0, &s1h)| (s0 + s1h).rem_euclid(Q))
        .collect();
    assert_eq!(
        reconstructed, msg_i32,
        "s0 + s1*h != msg_point (mod Q)"
    );
    println!("[5f] s0 + s1*h == msg_point (mod Q) -- PASS");

    println!("\n=== ALL CHECKS PASSED ===\n");
}
