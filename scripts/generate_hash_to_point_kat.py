#!/usr/bin/env python3
"""Generate hash_to_point KAT vectors for cross-language testing."""
import json
import sys
sys.path.insert(0, 'falcon.py')

from falcon import Falcon

falcon = Falcon(512)

# Test vectors with different messages and salts
test_cases = []

messages = [
    b"",
    b"Hello, Falcon!",
    b"Test",
    b"A" * 100,
]

salts = [
    bytes([0] * 40),
    bytes([1] * 40),
    bytes(range(40)),
    bytes([0xFF] * 40),
]

for msg in messages:
    for salt in salts:
        hashed = falcon._Falcon__hash_to_point__(msg, salt)
        test_cases.append({
            "message": msg.hex(),
            "salt": salt.hex(),
            "hash": hashed,
        })

print(json.dumps(test_cases, indent=2))
