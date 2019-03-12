use std::{
    convert::From,
    ops::{Deref, DerefMut, Index},
};

use serde_derive::{Deserialize, Serialize};

/// Nibble (half-byte) type.
// TODO: Should we use an enum with 16 options instead of u8?
pub type Nibble = u8;

/// Vector of nibbles.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NibbleVec(pub Vec<Nibble>);

impl NibbleVec {
    /// Create new vector of nibbles.
    pub fn new() -> Self {
        NibbleVec(Vec::new())
    }

    /// Convert a key into a vector of nibbles.
    pub fn from_key(key: &[u8]) -> Self {
        let mut nibbles = Vec::new();

        for byte in key {
            nibbles.push((byte >> 4) & 0x0fu8);
            nibbles.push(byte & 0x0fu8);
        }

        NibbleVec(nibbles)
    }

    /// Compute the common prefix of two nibbles.
    pub fn common_prefix<'a>(&'a self, other: &NibbleVec) -> &'a [Nibble] {
        let length = self
            .0
            .iter()
            .zip(other.iter())
            .take_while(|&(a, b)| a == b)
            .count();

        &self[..length]
    }
}

impl Deref for NibbleVec {
    type Target = Vec<Nibble>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NibbleVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> Index<T> for NibbleVec
where
    Vec<Nibble>: Index<T>,
{
    type Output = <Vec<Nibble> as Index<T>>::Output;

    fn index(&self, index: T) -> &Self::Output {
        &self.0[index]
    }
}

impl<'a> From<&'a [Nibble]> for NibbleVec {
    fn from(value: &'a [Nibble]) -> Self {
        NibbleVec(value.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_nibble_conversion() {
        let nibble = NibbleVec::from_key(b"\x12\x34\x56");
        assert_eq!(nibble, NibbleVec(vec![1, 2, 3, 4, 5, 6]));
    }

    #[test]
    fn test_common_prefix() {
        let nibble_a = NibbleVec::from_key(b"\x12\x34\x56");
        let nibble_b = NibbleVec::from_key(b"\x12\x36\x66");

        assert_eq!(nibble_a.common_prefix(&nibble_b), &[1, 2, 3]);
        assert_eq!(
            nibble_a.common_prefix(&nibble_b),
            nibble_b.common_prefix(&nibble_a)
        );
    }
}
