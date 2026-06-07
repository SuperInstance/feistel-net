//! Bit-level permutation networks.

/// A permutation that maps bit positions to other bit positions.
#[derive(Clone)]
pub struct Permutation {
    /// Maps source bit position to destination bit position.
    table: Vec<usize>,
    /// Inverse permutation.
    inverse: Vec<usize>,
}

impl Permutation {
    /// Create a permutation from a mapping table.
    /// table[i] = j means bit position i maps to position j.
    pub fn new(table: Vec<usize>) -> Self {
        let n = table.len();
        let mut inverse = vec![0usize; n];
        for (i, &j) in table.iter().enumerate() {
            assert!(j < n, "Permutation index out of range");
            inverse[j] = i;
        }
        Self { table, inverse }
    }

    /// Apply the permutation to a value with the given bit width.
    pub fn permute(&self, input: u64, width: usize) -> u64 {
        let mut output = 0u64;
        for i in 0..width {
            if (input >> i) & 1 == 1 {
                output |= 1u64 << self.table[i];
            }
        }
        output
    }

    /// Apply the inverse permutation.
    pub fn inverse_permute(&self, input: u64, width: usize) -> u64 {
        let mut output = 0u64;
        for i in 0..width {
            if (input >> i) & 1 == 1 {
                output |= 1u64 << self.inverse[i];
            }
        }
        output
    }

    /// Create a simple P-box that reverses bit order.
    pub fn reverse(width: usize) -> Self {
        let table: Vec<usize> = (0..width).rev().collect();
        Self::new(table)
    }

    /// Create a rotation permutation.
    pub fn rotate_left(width: usize, shift: usize) -> Self {
        let table: Vec<usize> =
            (0..width).map(|i| (i + shift) % width).collect();
        Self::new(table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permute_roundtrip() {
        let perm = Permutation::reverse(8);
        let val: u64 = 0b10110011;
        let p = perm.permute(val, 8);
        let inv = perm.inverse_permute(p, 8);
        assert_eq!(inv, val);
    }

    #[test]
    fn test_reverse_permutation() {
        let perm = Permutation::reverse(8);
        // 0b10110011 reversed is 0b11001101
        assert_eq!(perm.permute(0b10110011u64, 8), 0b11001101);
    }

    #[test]
    fn test_rotate_permutation() {
        let perm = Permutation::rotate_left(4, 1);
        // 0b1010 rotated left by 1 in 4-bit = 0b0101
        assert_eq!(perm.permute(0b1010u64, 4), 0b0101);
    }
}
