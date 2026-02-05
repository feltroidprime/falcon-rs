//! NIST AES-256-CTR-DRBG implementation for KAT reproduction.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;

/// AES-256-CTR-DRBG state.
pub struct NistDrbg {
    key: [u8; 32],
    v: [u8; 16],
    reseed_counter: u64,
}

impl NistDrbg {
    /// Create uninitialized DRBG.
    pub fn new() -> Self {
        NistDrbg {
            key: [0u8; 32],
            v: [0u8; 16],
            reseed_counter: 0,
        }
    }

    /// AES-256-ECB single block encryption.
    fn aes256_ecb(&self, input: &[u8; 16]) -> [u8; 16] {
        let cipher = Aes256::new((&self.key).into());
        let mut block = *input;
        cipher.encrypt_block((&mut block).into());
        block
    }

    /// Increment V as a 128-bit big-endian counter.
    fn increment_v(&mut self) {
        for i in (0..16).rev() {
            self.v[i] = self.v[i].wrapping_add(1);
            if self.v[i] != 0 {
                break;
            }
        }
    }

    /// Update Key and V using provided_data (48 bytes or None).
    fn update(&mut self, provided_data: Option<&[u8; 48]>) {
        let mut temp = [0u8; 48];

        for i in 0..3 {
            self.increment_v();
            let block = self.aes256_ecb(&self.v);
            temp[i * 16..(i + 1) * 16].copy_from_slice(&block);
        }

        if let Some(data) = provided_data {
            for i in 0..48 {
                temp[i] ^= data[i];
            }
        }

        self.key.copy_from_slice(&temp[..32]);
        self.v.copy_from_slice(&temp[32..48]);
    }

    /// Initialize DRBG with 48-byte entropy input.
    pub fn init(&mut self, entropy: &[u8; 48], personalization: Option<&[u8; 48]>) {
        let mut seed_material = *entropy;
        if let Some(pers) = personalization {
            for i in 0..48 {
                seed_material[i] ^= pers[i];
            }
        }

        self.key = [0u8; 32];
        self.v = [0u8; 16];
        self.update(Some(&seed_material));
        self.reseed_counter = 1;
    }

    /// Generate random bytes.
    pub fn generate(&mut self, output: &mut [u8]) {
        let mut pos = 0;
        while pos < output.len() {
            self.increment_v();
            let block = self.aes256_ecb(&self.v);
            let copy_len = (output.len() - pos).min(16);
            output[pos..pos + copy_len].copy_from_slice(&block[..copy_len]);
            pos += copy_len;
        }

        self.update(None);
        self.reseed_counter += 1;
    }

    /// Generate and return a Vec of random bytes.
    pub fn generate_vec(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut output = vec![0u8; num_bytes];
        self.generate(&mut output);
        output
    }
}

impl Default for NistDrbg {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drbg_deterministic() {
        let seed: [u8; 48] = core::array::from_fn(|i| i as u8);

        let mut drbg1 = NistDrbg::new();
        drbg1.init(&seed, None);
        let out1 = drbg1.generate_vec(32);

        let mut drbg2 = NistDrbg::new();
        drbg2.init(&seed, None);
        let out2 = drbg2.generate_vec(32);

        assert_eq!(out1, out2);
    }
}
