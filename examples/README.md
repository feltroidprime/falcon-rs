# Examples

## Basic Usage

```bash
cargo run --example basic_usage --features shake
```

This example demonstrates:
1. Key generation
2. Signing a message
3. Verifying the signature
4. Verification failure with wrong message
5. Serialization and deserialization of keys and signatures

## WASM Usage

See the [main README](../README.md#wasm-build) for WASM build instructions.

Example JavaScript usage:

```javascript
import init, { generate_keypair, sign, verify } from './pkg/falcon_rs.js';

async function demo() {
    await init();

    // Generate keypair
    const { signing_key, verifying_key } = generate_keypair();

    // Sign message
    const message = new TextEncoder().encode("Hello!");
    const signature = sign(signing_key, message);

    // Verify
    const valid = verify(verifying_key, message, signature);
    console.log("Valid:", valid);
}

demo();
```
