//! Key schedule for deriving round keys from a master key.

/// Key schedule that expands a master key into round subkeys.
#[derive(Clone)]
pub struct KeySchedule {
    /// Round subkeys.
    round_keys: Vec<u64>,
}

impl KeySchedule {
    /// Create a new key schedule from a master key and the number of rounds.
    ///
    /// Uses a simple key expansion: each round key is derived by mixing
    /// the master key with the round number using ARX (Add-Rotate-XOR).
    pub fn new(master_key: &[u8], num_rounds: usize) -> Self {
        // Convert master key to one or more u64 seed values
        let seed = Self::bytes_to_u64(master_key);
        let round_keys: Vec<u64> = (0..num_rounds)
            .map(|i| {
                let r = i as u64;
                let mut k = seed;
                k = k.wrapping_add(r.wrapping_mul(0x9e3779b97f4a7c15));
                k ^= k.rotate_right(17);
                k = k.wrapping_mul(0x517cc1b727220a95);
                k ^= k.rotate_right(31);
                k
            })
            .collect();
        Self { round_keys }
    }

    /// Get the round key for a specific round.
    ///
    /// # Panics
    /// Panics if round >= number of rounds.
    pub fn round_key(&self, round: usize) -> u64 {
        self.round_keys[round]
    }

    /// Get the number of rounds.
    pub fn num_rounds(&self) -> usize {
        self.round_keys.len()
    }

    /// Get all round keys.
    pub fn all_keys(&self) -> &[u64] {
        &self.round_keys
    }

    /// Check that no two round keys are identical.
    pub fn keys_are_unique(&self) -> bool {
        for i in 0..self.round_keys.len() {
            for j in (i + 1)..self.round_keys.len() {
                if self.round_keys[i] == self.round_keys[j] {
                    return false;
                }
            }
        }
        true
    }

    /// Convert arbitrary-length key bytes to a u64 seed.
    fn bytes_to_u64(key: &[u8]) -> u64 {
        let mut hash: u64 = 0x517cc1b727220a95;
        for (i, &byte) in key.iter().enumerate() {
            hash ^= (byte as u64).wrapping_shl(((i % 8) * 8) as u32);
            hash = hash.wrapping_mul(0x5bd1e9955bd1e995);
            hash ^= hash.rotate_right(47);
        }
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keys_are_unique() {
        let ks = KeySchedule::new(b"my-secret-key", 16);
        assert!(ks.keys_are_unique());
    }

    #[test]
    fn test_deterministic() {
        let ks1 = KeySchedule::new(b"test-key", 8);
        let ks2 = KeySchedule::new(b"test-key", 8);
        for i in 0..8 {
            assert_eq!(ks1.round_key(i), ks2.round_key(i));
        }
    }

    #[test]
    fn test_different_keys_differ() {
        let ks1 = KeySchedule::new(b"key-one", 4);
        let ks2 = KeySchedule::new(b"key-two", 4);
        let mut any_different = false;
        for i in 0..4 {
            if ks1.round_key(i) != ks2.round_key(i) {
                any_different = true;
                break;
            }
        }
        assert!(any_different);
    }

    #[test]
    fn test_num_rounds() {
        let ks = KeySchedule::new(b"key", 32);
        assert_eq!(ks.num_rounds(), 32);
        assert_eq!(ks.all_keys().len(), 32);
    }
}
