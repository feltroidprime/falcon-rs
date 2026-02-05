#!/usr/bin/env python3
"""Compare DRBG output between Python and Rust implementations."""
import subprocess
import sys
sys.path.insert(0, 'falcon.py')

from nist_drbg import NistDrbg

def main():
    # Use first KAT seed
    seed = bytes.fromhex(
        "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7"
        "056A8C266F9EF97ED08541DBD2E1FFA1"
    )

    # Python output
    drbg = NistDrbg()
    drbg.init(seed, b'')
    py_out = drbg.generate(64)
    print(f"Python: {py_out.hex()}")

    # Rust output (via test binary)
    print("\nTo compare with Rust, run:")
    print("  cargo test --features shake test_drbg_kat_seed -- --nocapture")


if __name__ == '__main__':
    main()
