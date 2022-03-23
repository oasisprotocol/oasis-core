//! Nonce utility used to ensure nonces are safely incremented.
use std::ops::Deref;

use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

/// Size of the nonce in bytes.
pub use super::deoxysii::NONCE_SIZE;
/// Size of tag portion of the nonce in bytes. These bytes will never update.
pub const TAG_SIZE: usize = 11;

/// 120 bit nonce with a 88 bit tag and 32 bit counter. If the counter exceeds
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
        // Extract the current counter out of the nonce.
        let mut counter_array = &self.current_value[TAG_SIZE..];
        // Increment the count and wrap to 0 if necessary.
        let new_counter: u32 = {
            let mut counter = counter_array.read_u32::<BigEndian>().unwrap();
            // If about to overflow wrap around to 0.
            if counter == !0u32 {
                counter = 0;
            } else {
                counter += 1;
            }
            counter
        };
        // Merge this new counter back into the nonce.
        let new_value: [u8; NONCE_SIZE] = {
            let mut new_value_vec = self.current_value[..TAG_SIZE].to_vec();
            new_value_vec.write_u32::<BigEndian>(new_counter).unwrap();

            assert!(new_value_vec.len() == NONCE_SIZE);

            let mut new_value = [0; NONCE_SIZE];
            new_value.copy_from_slice(&new_value_vec);
            new_value
        };
        // If we've exhausted all 2^32 counters, then error.
        if new_value == self.start_value {
            return Err(anyhow!(
                "This nonce has been exhausted, and a new one must be created",
            ));
        }
        // Update is valid, so mutate.
        self.current_value = new_value;
        // Success.
        Ok(())
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
        let inner = [0; 15];
        let mut nonce = Nonce::new(inner);
        nonce.increment().unwrap();
        let mut expected = [0; 15];
        expected[14] = 1;
        assert_eq!(nonce.to_vec(), expected.to_vec());
    }

    #[test]
    fn test_increment_one() {
        let mut start_value = [0; 15];
        start_value[14] = 1;
        let mut nonce = Nonce::new(start_value);
        nonce.increment().unwrap();
        let mut expected = [0; 15];
        expected[14] = 2;

        assert_eq!(nonce.to_vec(), expected.to_vec());
    }

    #[test]
    fn test_increment_carry() {
        let start_value = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255];
        let mut nonce = Nonce::new(start_value);
        nonce.increment().unwrap();
        let expected = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0];
        assert_eq!(nonce.to_vec(), expected.to_vec());
    }

    #[test]
    fn test_increment_overflow() {
        let start_value = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255];
        let mut nonce = Nonce::new(start_value);
        nonce.increment().unwrap();
        let expected = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(nonce.to_vec(), expected.to_vec());
    }

    #[test]
    fn test_increment_exhaustion() {
        let start_value = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255];
        let current_value = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 254];
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
        let start_value = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255];
        let current_value = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 253];
        let mut nonce = Nonce {
            start_value,
            current_value,
        };
        let first_expected = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 254];
        nonce.increment().unwrap();
        assert_eq!(nonce.to_vec(), first_expected.to_vec());
        assert_eq!(nonce.increment().is_err(), true);
    }
}
