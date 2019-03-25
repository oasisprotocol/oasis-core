use crate::common::crypto::hash::Hash;

/// Get a single bit from the given hash.
pub fn get_key_bit(key: &Hash, bit: u8) -> bool {
    (key.0[(bit / 8) as usize] & (1 << (7 - (bit % 8)))) != 0
}

/// Set a single bit in the given hash and return the result.
pub fn set_key_bit(key: &Hash, bit: u8, val: bool) -> Hash {
    let mut hash = *key;
    let mask = (1 << (7 - (bit % 8))) as u8;
    if val {
        hash.0[(bit / 8) as usize] |= mask;
    } else {
        hash.0[(bit / 8) as usize] &= !mask;
    }
    hash
}
