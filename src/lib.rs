//! Feistel network cipher construction library.
//!
//! Provides balanced and unbalanced Feistel networks, key scheduling,
//! S-box design, permutation networks, and round functions.

pub mod feistel;
pub mod key_schedule;
pub mod permutation;
pub mod round;
pub mod sbox;

pub use feistel::{BalancedFeistel, UnbalancedFeistel};
pub use key_schedule::KeySchedule;
pub use sbox::SBox;
