#!/usr/bin/env python3
"""Extract FFT and NTT constants for n=512 from Python implementation."""
import sys
sys.path.insert(0, 'falcon.py')

from fft_constants import roots_dict
from ntt_constants import roots_dict_Zq, inv_mod_q

# Extract FFT roots for n=512 (complex numbers)
fft_roots = roots_dict[512]
print("// FFT roots of unity (complex) for n=512")
print("pub const FFT_ROOTS: [(f64, f64); 512] = [")
for i, r in enumerate(fft_roots):
    print(f"    ({r.real:.17}, {r.imag:.17}),")
print("];")
print()

# Extract NTT roots for n=512
ntt_roots = roots_dict_Zq[512]
print("// NTT roots of unity mod q for n=512")
print("pub const NTT_ROOTS: [i32; 512] = [")
for i in range(0, 512, 8):
    line = ", ".join(str(ntt_roots[j]) for j in range(i, min(i+8, 512)))
    print(f"    {line},")
print("];")
print()

# Extract inverse mod q table (needed for division)
print("// Inverse mod q lookup table (inv_mod_q[i] = i^-1 mod q)")
print("pub const INV_MOD_Q: [i32; 12289] = [")
for i in range(0, 12289, 16):
    line = ", ".join(str(inv_mod_q[j] if j < len(inv_mod_q) else 0) for j in range(i, min(i+16, 12289)))
    print(f"    {line},")
print("];")
