//! Nonce utility used to ensure nonces are safely incremented.

use super::error::{Error, Result};
use std::ops::Deref;

/// Recommended size of the nonce in bytes.
pub const NONCE_SIZE: usize = 16;

/// 128 bit nonce with a 96 bit tag and 32 bit counter. If the counter exceeds
/// 32 bits, then the nonce is no longer valid and must be refreshed with a new
/// random nonce. It is expected that all 128 bits are given randomly. However,
/// the last 32 counting bits may wrap around to ensure 2^32 counts may be used
/// per nonce.
#[derive(Debug, Clone)]
pub struct Nonce {
    /// The current value of the nonce, from which we may increment.
    current_value: [u8; NONCE_SIZE],
    /// The initial value of the nonce, used to ensure we never allow the nonce
    /// to be the same again (after incrementing 2^32 times).
    start_value: [u8; NONCE_SIZE],
}

impl Nonce {
    pub fn new(start_value: [u8; NONCE_SIZE]) -> Self {
        Nonce {
            current_value: start_value,
            start_value,
        }
    }
    /// Adds one to the nonce, affecting only the last 32 counting bits.
    /// Returns an error iff we've exceeded our nonce's counter capacity, i.e.,
    /// we've incremented 2^32 times. In this case, the Nonce remains unchanged,
    /// and all subsequent calls to this method will return an Error.
    pub fn increment(&mut self) -> Result<()> {
        let mut carry = 1;
        // The current byte we're incrementing.
        let mut byte_index = self.current_value.len() - 1;
        // The value of `byte_index` before incrementing.
        let mut old_byte = self.current_value[byte_index];

        while carry == 1 {
            // Track the old value in case we need to revert the increment.
            old_byte = self.current_value[byte_index];
            // Increment as u64 to maintain aa potential carry.
            carry += self.current_value[byte_index] as u64;
            // Remove the potential carry to update the new byte position.
            self.current_value[byte_index] = carry as u8;
            // Extract out the carry.
            carry /= 256;
            // Move onto the next byte.
            byte_index -= 1;
            // Allow the counter to wrap around.
            if self.overflows_counter(byte_index) {
                break;
            }
        }
        // If we've exhausted all 2^32 counters.
        if self.current_value == self.start_value {
            // Undo the change and return an error.
            self.current_value[byte_index + 1] = old_byte;
            return Err(Error::new(
                "This nonce has been exhausted, and a new one must be created",
            ));
        }
        Ok(())
    }

    /// Returns true iff `byte_index` is past our 32 bit counter.
    fn overflows_counter(&self, byte_index: usize) -> bool {
        byte_index == self.current_value.len() - 1 - 4
    }
}

impl Deref for Nonce {
    type Target = [u8; NONCE_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.current_value
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_increment_zero() {
        let inner = [0; 16];
        let mut nonce = Nonce::new(inner);
        nonce.increment().unwrap();
        let mut expected = [0; 16];
        expected[15] = 1;
        assert_eq!(nonce.to_vec(), expected.to_vec());
    }

    #[test]
    fn test_increment_one() {
        let mut start_value = [0; 16];
        start_value[15] = 1;
        let mut nonce = Nonce::new(start_value);
        nonce.increment().unwrap();
        let mut expected = [0; 16];
        expected[15] = 2;

        assert_eq!(nonce.to_vec(), expected.to_vec());
    }

    #[test]
    fn test_increment_carry() {
        let start_value = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255];
        let mut nonce = Nonce::new(start_value);
        nonce.increment().unwrap();
        let expected = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0];
        assert_eq!(nonce.to_vec(), expected.to_vec());
    }

    #[test]
    fn test_increment_overflow() {
        let start_value = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255];
        let mut nonce = Nonce::new(start_value);
        nonce.increment().unwrap();
        let expected = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(nonce.to_vec(), expected.to_vec());
    }

    #[test]
    fn test_increment_exhaustion() {
        let start_value = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255];
        let current_value = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 254];
        let mut nonce = Nonce {
            start_value,
            current_value,
        };
        assert_eq!(nonce.increment().is_err(), true);
        // Try again.
        assert_eq!(nonce.increment().is_err(), true);
    }

    #[test]
    fn test_double_increment_exhaustion() {
        let start_value = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255];
        let current_value = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 253];
        let mut nonce = Nonce {
            start_value,
            current_value,
        };
        let first_expected = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 254];
        nonce.increment().unwrap();
        assert_eq!(nonce.to_vec(), first_expected.to_vec());
        assert_eq!(nonce.increment().is_err(), true);
    }
}
