//! S-box (Substitution Box) design and analysis.
//!
//! Provides configurable S-boxes with nonlinearity measurement,
//! strict avalanche criterion checks, and construction utilities.

/// A substitution box mapping 8-bit values to 8-bit values.
#[derive(Clone)]
pub struct SBox {
    /// The substitution table (256 entries for all possible byte inputs).
    table: [u8; 256],
    /// Inverse table for reverse lookup.
    inverse: [u8; 256],
}

impl SBox {
    /// Create a new S-box from a 256-byte lookup table.
    ///
    /// # Panics
    /// Panics if the table is not a permutation of 0..255.
    pub fn new(table: [u8; 256]) -> Self {
        let mut seen = [false; 256];
        for &v in &table {
            let idx = v as usize;
            if seen[idx] {
                panic!("S-box must be a permutation (duplicate value: {v})");
            }
            seen[idx] = true;
        }
        let mut inverse = [0u8; 256];
        for (i, &v) in table.iter().enumerate() {
            inverse[v as usize] = i as u8;
        }
        Self { table, inverse }
    }

    /// Apply the S-box substitution to a byte.
    pub fn substitute(&self, input: u8) -> u8 {
        self.table[input as usize]
    }

    /// Apply the inverse S-box substitution.
    pub fn inverse_substitute(&self, output: u8) -> u8 {
        self.inverse[output as usize]
    }

    /// Get a reference to the substitution table.
    pub fn table(&self) -> &[u8; 256] {
        &self.table
    }

    /// Compute the nonlinearity of the S-box.
    /// Returns the minimum nonlinearity across all 8 Boolean component functions.
    /// Higher values indicate better resistance to linear cryptanalysis.
    pub fn nonlinearity(&self) -> u32 {
        let mut min_nl = u32::MAX;
        for bit in 0..8u32 {
            // Extract the Boolean function for this output bit
            let f: Vec<u8> = (0u32..256)
                .map(|x| (self.table[x as usize] >> bit) & 1)
                .collect();

            // Compute Walsh-Hadamard transform
            let mut wh = vec![0i32; 256];
            for i in 0..256 {
                wh[i] = if f[i] == 0 { 1 } else { -1 };
            }

            // Iterative Walsh-Hadamard transform
            let mut stride = 1;
            while stride < 256 {
                for i in (0..256).step_by(2 * stride) {
                    for j in 0..stride {
                        let a = wh[i + j];
                        let b = wh[i + j + stride];
                        wh[i + j] = a + b;
                        wh[i + j + stride] = a - b;
                    }
                }
                stride *= 2;
            }

            // Nonlinearity = 2^(n-1) - 0.5 * max|W(f)|
            let max_abs = wh.iter().map(|v| v.abs()).max().unwrap_or(0) as u32;
            let nl = 128 - max_abs / 2;
            min_nl = min_nl.min(nl);
        }
        min_nl
    }

    /// Generate a pseudo-random S-box from a seed using simple hash-like construction.
    pub fn from_seed(seed: u64) -> Self {
        let mut table: [u8; 256] = core::array::from_fn(|i| i as u8);
        let mut rng = seed;
        // Fisher-Yates shuffle with seed-derived randomness
        for i in (1..256).rev() {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let j = (rng >> 33) as usize % (i + 1);
            table.swap(i, j);
        }
        Self::new(table)
    }
}

/// A simple identity S-box (no substitution).
pub fn identity_sbox() -> SBox {
    let table: [u8; 256] = core::array::from_fn(|i| i as u8);
    SBox::new(table)
}

/// AES-like S-box (standard Rijndael S-box).
pub fn aes_sbox() -> SBox {
    const AES_SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ];
    SBox::new(AES_SBOX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbox_is_permutation() {
        let sbox = SBox::from_seed(42);
        let mut seen = [false; 256];
        for i in 0u32..256 {
            let out = sbox.substitute(i as u8) as usize;
            assert!(!seen[out], "Duplicate output at index {i}");
            seen[out] = true;
        }
    }

    #[test]
    fn test_sbox_inverse_roundtrip() {
        let sbox = SBox::from_seed(12345);
        for i in 0u32..256 {
            let sub = sbox.substitute(i as u8);
            assert_eq!(sbox.inverse_substitute(sub), i as u8);
        }
    }

    #[test]
    fn test_aes_sbox_nonlinearity() {
        let sbox = aes_sbox();
        let nl = sbox.nonlinearity();
        // AES S-box has nonlinearity of 112
        assert!(nl >= 100, "AES S-box nonlinearity too low: {nl}");
    }

    #[test]
    fn test_identity_sbox() {
        let sbox = identity_sbox();
        for i in 0u32..256 {
            assert_eq!(sbox.substitute(i as u8), i as u8);
        }
    }

    #[test]
    #[should_panic]
    fn test_invalid_sbox_panics() {
        let bad_table = [0u8; 256]; // all zeros, not a permutation
        let _ = SBox::new(bad_table);
    }
}
