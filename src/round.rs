//! Round function primitives for Feistel networks.

use crate::sbox::SBox;

/// A round function suitable for use in Feistel networks.
pub trait RoundFunction {
    /// Apply the round function to the input half-block using the given round key.
    fn round(&self, input: u32, round_key: u64) -> u32;
}

/// A simple round function using S-box substitution, rotation, and key mixing.
pub struct SimpleRound {
    sbox: SBox,
}

impl SimpleRound {
    /// Create a new simple round function with the given S-box.
    pub fn new(sbox: SBox) -> Self {
        Self { sbox }
    }

    /// Create with the AES S-box.
    pub fn aes() -> Self {
        Self { sbox: crate::sbox::aes_sbox() }
    }
}

impl RoundFunction for SimpleRound {
    fn round(&self, input: u32, round_key: u64) -> u32 {
        // Split input into 4 bytes, apply S-box to each
        let b0 = self.sbox.substitute((input & 0xFF) as u8);
        let b1 = self.sbox.substitute(((input >> 8) & 0xFF) as u8);
        let b2 = self.sbox.substitute(((input >> 16) & 0xFF) as u8);
        let b3 = self.sbox.substitute(((input >> 24) & 0xFF) as u8);

        let mut out = (b0 as u32)
            | ((b1 as u32) << 8)
            | ((b2 as u32) << 16)
            | ((b3 as u32) << 24);

        // Mix with round key
        out ^= (round_key & 0xFFFFFFFF) as u32;
        // Rotate
        out = out.rotate_left(7);
        // Second key mix
        out ^= ((round_key >> 32) & 0xFFFFFFFF) as u32;
        out = out.rotate_left(11);

        out
    }
}

/// Compute the avalanche score: how many output bits flip when one input bit flips.
/// Returns (min_flips, max_flips, avg_flips) across all single-bit changes.
pub fn avalanche_score<F>(f: &F, input: u32, key: u64) -> (u32, u32, f64)
where
    F: RoundFunction,
{
    let base = f.round(input, key);
    let mut min_flip = u32::MAX;
    let mut max_flip = 0u32;
    let mut total_flip = 0u32;
    let n = 32; // number of bits

    for bit in 0..n {
        let flipped = input ^ (1u32 << bit);
        let out = f.round(flipped, key);
        let diff = (base ^ out).count_ones();
        min_flip = min_flip.min(diff);
        max_flip = max_flip.max(diff);
        total_flip += diff;
    }

    let avg = total_flip as f64 / n as f64;
    (min_flip, max_flip, avg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_deterministic() {
        let rf = SimpleRound::aes();
        let input = 0xdeadbeef;
        let key = 0x1234567890abcdef;
        assert_eq!(rf.round(input, key), rf.round(input, key));
    }

    #[test]
    fn test_round_differs_per_key() {
        let rf = SimpleRound::aes();
        let input = 0x42;
        let out1 = rf.round(input, 0x1111);
        let out2 = rf.round(input, 0x2222);
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_avalanche() {
        let rf = SimpleRound::aes();
        let (_, _, avg) = avalanche_score(&rf, 0x12345678, 0xabcdef);
        // Good avalanche: average flips should be close to 16 (half of 32 bits)
        assert!(avg > 4.0, "Avalanche too weak: avg={avg}");
    }
}
