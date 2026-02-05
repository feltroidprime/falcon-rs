#!/usr/bin/env python3
"""Generate sign/verify KAT vectors for Rust testing."""
import json
import sys
sys.path.insert(0, 'falcon.py')

from falcon import Falcon

# Generate a keypair and sign a few messages
falcon = Falcon(512)
sk, vk = falcon.keygen()

# Extract the raw polynomials from sk
(f, g, F, G, B0_fft, T_fft) = sk

# Generate test vectors
test_vectors = []

messages = [
    b"Hello, Falcon!",
    b"Test message 123",
    b"",  # Empty message
    b"A" * 100,  # Longer message
]

for msg in messages:
    sig = falcon.sign(sk, msg)

    # Verify it works
    assert falcon.verify(vk, msg, sig), f"Verification failed for message: {msg}"

    test_vectors.append({
        "message": msg.hex(),
        "signature": sig.hex(),
    })

output = {
    "public_key": vk.hex(),
    "test_cases": test_vectors,
}

print(json.dumps(output, indent=2))
