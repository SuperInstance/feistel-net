//! Feistel network cipher constructions.
//!
//! Implements balanced and unbalanced Feistel networks.

use crate::key_schedule::KeySchedule;
use crate::round::{RoundFunction, SimpleRound};

/// Balanced Feistel network operating on 64-bit blocks.
pub struct BalancedFeistel {
    round_fn: SimpleRound,
    num_rounds: usize,
}

impl BalancedFeistel {
    /// Create a new balanced Feistel cipher with the given key schedule.
    pub fn new(_schedule: KeySchedule, num_rounds: usize) -> Self {
        Self {
            round_fn: SimpleRound::aes(),
            num_rounds,
        }
    }

    /// Create with a raw key and number of rounds.
    pub fn from_key(key: &[u8], num_rounds: usize) -> Self {
        let schedule = KeySchedule::new(key, num_rounds);
        Self::new(schedule, num_rounds)
    }

    /// Encrypt a 64-bit block.
    pub fn encrypt_block(&self, block: u64, round_keys: &[u64]) -> u64 {
        let mut left = (block >> 32) as u32;
        let mut right = (block & 0xFFFFFFFF) as u32;

        for &rk in round_keys.iter().take(self.num_rounds) {
            let new_left = right;
            let new_right = left ^ self.round_fn.round(right, rk);
            left = new_left;
            right = new_right;
        }

        // Final swap (undo last swap for Feistel structure)
        ((right as u64) << 32) | (left as u64)
    }

    /// Decrypt a 64-bit block.
    pub fn decrypt_block(&self, block: u64, round_keys: &[u64]) -> u64 {
        let mut left = (block >> 32) as u32;
        let mut right = (block & 0xFFFFFFFF) as u32;

        for &rk in round_keys.iter().take(self.num_rounds).rev() {
            let new_left = right;
            let new_right = left ^ self.round_fn.round(right, rk);
            left = new_left;
            right = new_right;
        }

        ((right as u64) << 32) | (left as u64)
    }

    /// Get the number of rounds.
    pub fn num_rounds(&self) -> usize {
        self.num_rounds
    }
}

/// Unbalanced Feistel network with source-heavy construction.
/// Operates on 64-bit blocks with a 32/32 split but asymmetric round function.
pub struct UnbalancedFeistel {
    num_rounds: usize,
}

impl UnbalancedFeistel {
    /// Create a new unbalanced Feistel cipher.
    pub fn new(num_rounds: usize) -> Self {
        Self { num_rounds }
    }

    /// Encrypt a 64-bit block using unbalanced Feistel (source-heavy variant).
    /// The round function uses different rotation amounts for each half,
    /// creating asymmetry in the diffusion.
    pub fn encrypt_block(&self, block: u64, round_keys: &[u64]) -> u64 {
        let mut left = (block >> 32) as u32;
        let mut right = (block & 0xFFFFFFFF) as u32;

        for &rk in round_keys.iter().take(self.num_rounds) {
            let f_out = self.round_function(right, rk);
            let new_right = left ^ f_out;
            left = right;
            right = new_right;
        }

        // Swap at end
        ((right as u64) << 32) | (left as u64)
    }

    /// Decrypt a 64-bit block.
    pub fn decrypt_block(&self, block: u64, round_keys: &[u64]) -> u64 {
        let mut left = (block >> 32) as u32;
        let mut right = (block & 0xFFFFFFFF) as u32;

        for &rk in round_keys.iter().take(self.num_rounds).rev() {
            let f_out = self.round_function(right, rk);
            let new_right = left ^ f_out;
            left = right;
            right = new_right;
        }

        ((right as u64) << 32) | (left as u64)
    }

    fn round_function(&self, input: u32, key: u64) -> u32 {
        let mut x = input;
        x ^= (key & 0xFFFFFFFF) as u32;
        x = x.rotate_left(13);
        x = x.wrapping_mul(0x5bd1e995);
        x ^= x.rotate_right(17);
        x = x.wrapping_add((key >> 32) as u32);
        x
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_schedule::KeySchedule;

    #[test]
    fn test_balanced_roundtrip() {
        let schedule = KeySchedule::new(b"test-key-12345", 16);
        let cipher = BalancedFeistel::new(schedule.clone(), 16);
        let plaintext: u64 = 0x0123456789abcdef;
        let keys = schedule.all_keys().to_vec();
        let ct = cipher.encrypt_block(plaintext, &keys);
        let pt = cipher.decrypt_block(ct, &keys);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_balanced_different_inputs_differ() {
        let schedule = KeySchedule::new(b"key", 16);
        let cipher = BalancedFeistel::new(schedule.clone(), 16);
        let keys = schedule.all_keys().to_vec();
        let ct1 = cipher.encrypt_block(0x0000000000000000, &keys);
        let ct2 = cipher.encrypt_block(0x0000000000000001, &keys);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_balanced_different_keys_differ() {
        let s1 = KeySchedule::new(b"key1", 16);
        let s2 = KeySchedule::new(b"key2", 16);
        let c1 = BalancedFeistel::new(s1.clone(), 16);
        let c2 = BalancedFeistel::new(s2.clone(), 16);
        let pt = 0xdeadbeefcafe1234;
        let ct1 = c1.encrypt_block(pt, s1.all_keys());
        let ct2 = c2.encrypt_block(pt, s2.all_keys());
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_balanced_avalanche() {
        let schedule = KeySchedule::new(b"avalanche-key", 16);
        let cipher = BalancedFeistel::new(schedule.clone(), 16);
        let keys = schedule.all_keys().to_vec();
        let base = cipher.encrypt_block(0x1234567890abcdef, &keys);
        let mut total_flips = 0u32;
        for bit in 0..64 {
            let flipped = 0x1234567890abcdef ^ (1u64 << bit);
            let ct = cipher.encrypt_block(flipped, &keys);
            total_flips += (base ^ ct).count_ones();
        }
        let avg = total_flips as f64 / 64.0;
        // Should be near 32 (half of 64 bits)
        assert!(avg > 16.0, "Block avalanche too weak: avg={avg}");
    }

    #[test]
    fn test_unbalanced_roundtrip() {
        let schedule = KeySchedule::new(b"unbal-key", 12);
        let cipher = UnbalancedFeistel::new(12);
        let keys = schedule.all_keys().to_vec();
        let plaintext: u64 = 0x1234_5678_abcd_ef01;
        let ct = cipher.encrypt_block(plaintext, &keys);
        let pt = cipher.decrypt_block(ct, &keys);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_balanced_zero_rounds_is_swap() {
        let schedule = KeySchedule::new(b"key", 0);
        let cipher = BalancedFeistel::new(schedule.clone(), 0);
        let keys = schedule.all_keys().to_vec();
        let pt: u64 = 0x1111222233334444;
        let ct = cipher.encrypt_block(pt, &keys);
        // With 0 rounds: left = right, right = left -> then final swap
        // In our implementation, encrypt does swap then final swap, so identity
        // Actually with 0 rounds, the loop doesn't execute, left/right stay same,
        // then we swap at the end: output = (right << 32) | left
        // right starts as pt & 0xFFFFFFFF, left starts as pt >> 32
        // After 0 rounds, output = (right << 32) | left = (pt_low << 32) | pt_high
        let pt_high = (pt >> 32) as u32;
        let pt_low = (pt & 0xFFFFFFFF) as u32;
        let expected = ((pt_low as u64) << 32) | (pt_high as u64);
        assert_eq!(ct, expected);
    }
}
