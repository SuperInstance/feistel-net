# feistel-net

A pure-Rust implementation of Feistel network cipher constructions with no external dependencies.

## Features

- **Balanced Feistel Network** — Classic equal-half construction
- **Unbalanced Feistel Network** — Asymmetric split with source-heavy/target-heavy variants
- **Key Schedule** — Derivation of round keys from a master key
- **S-box Design** — Substitution boxes with nonlinearity analysis
- **Permutation Networks** — Bit-level permutation primitives
- **Round Function** — Configurable round functions with avalanche properties

## Usage

```rust
use feistel_net::{feistel::BalancedFeistel, key_schedule::KeySchedule, sbox::SBox};

let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6];
let schedule = KeySchedule::new(&key, 16);
let cipher = BalancedFeistel::new(schedule, 64);

let plaintext: u64 = 0x0123456789abcdef;
let ciphertext = cipher.encrypt(plaintext);
let decrypted = cipher.decrypt(ciphertext);
assert_eq!(decrypted, plaintext);
```

## Test Coverage

18+ tests covering encryption/decryption roundtrip, avalanche criterion, key schedule properties, and S-box nonlinearity.

## License

MIT OR Apache-2.0
