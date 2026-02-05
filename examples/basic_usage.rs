//! Basic usage example for falcon-rs.
//!
//! Run with: cargo run --example basic_usage --features shake

use falcon_rs::falcon::{Falcon, Signature, VerifyingKey};
use falcon_rs::hash_to_point::Shake256Hash;

fn main() {
    println!("Falcon-512 Post-Quantum Signature Example");
    println!("==========================================\n");

    // Step 1: Generate a keypair
    println!("1. Generating keypair...");
    let (secret_key, verifying_key) = Falcon::<Shake256Hash>::keygen();
    println!("   Keypair generated successfully!");

    // Step 2: Sign a message
    let message = b"Hello, post-quantum world!";
    println!("\n2. Signing message: {:?}", String::from_utf8_lossy(message));
    let signature = Falcon::<Shake256Hash>::sign(&secret_key, message);
    println!("   Message signed successfully!");
    println!("   Signature length: {} bytes", signature.to_bytes().len());

    // Step 3: Verify the signature
    println!("\n3. Verifying signature...");
    match Falcon::<Shake256Hash>::verify(&verifying_key, message, &signature) {
        Ok(true) => println!("   Signature is VALID!"),
        Ok(false) => println!("   Signature is INVALID!"),
        Err(e) => println!("   Verification error: {}", e),
    }

    // Step 4: Demonstrate verification failure with wrong message
    let wrong_message = b"This is a different message";
    println!("\n4. Verifying with wrong message: {:?}", String::from_utf8_lossy(wrong_message));
    match Falcon::<Shake256Hash>::verify(&verifying_key, wrong_message, &signature) {
        Ok(true) => println!("   Signature is VALID (unexpected!)"),
        Ok(false) => println!("   Signature is INVALID (expected behavior)"),
        Err(e) => println!("   Verification error: {}", e),
    }

    // Step 5: Demonstrate serialization/deserialization
    println!("\n5. Testing serialization/deserialization...");

    // Serialize public key
    let pk_bytes = verifying_key.to_bytes();
    println!("   Public key: {} bytes", pk_bytes.len());

    // Deserialize public key
    let restored_vk = VerifyingKey::from_bytes(&pk_bytes).expect("Failed to deserialize public key");

    // Serialize signature
    let sig_bytes = signature.to_bytes();
    println!("   Signature: {} bytes", sig_bytes.len());

    // Deserialize signature
    let restored_sig = Signature::from_bytes(&sig_bytes).expect("Failed to deserialize signature");

    // Verify with restored key and signature
    match Falcon::<Shake256Hash>::verify(&restored_vk, message, &restored_sig) {
        Ok(true) => println!("   Verification with restored key/signature: VALID!"),
        Ok(false) => println!("   Verification with restored key/signature: INVALID!"),
        Err(e) => println!("   Verification error: {}", e),
    }

    println!("\nExample completed successfully!");
}
