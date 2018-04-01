use std::marker::Sized;

/// Parse error.
#[derive(Copy, Clone, Debug)]
pub enum ParseError {
    InvalidLength,
    InvalidCharacter,
}

/// Type which can be parsed from a hex-encoded string.
pub trait HexEncoded {
    const LEN: usize;

    fn inner(&mut self, index: usize) -> &mut u8;

    fn from_hex(s: &str) -> Result<Self, ParseError>
    where
        Self: Sized + Default,
    {
        let mut result = Self::default();

        if s.len() != 2 * Self::LEN {
            return Err(ParseError::InvalidLength);
        }

        let mut modulus = 0;
        let mut buf = 0;
        let mut output_idx = 0;

        for byte in s.bytes() {
            buf <<= 4;

            match byte {
                b'A'...b'F' => buf |= byte - b'A' + 10,
                b'a'...b'f' => buf |= byte - b'a' + 10,
                b'0'...b'9' => buf |= byte - b'0',
                _ => return Err(ParseError::InvalidCharacter),
            }

            modulus += 1;
            if modulus == 2 {
                modulus = 0;
                *result.inner(output_idx) = buf;
                output_idx += 1;
            }
        }

        Ok(result)
    }
}

#[macro_export]
macro_rules! hex_encoded_struct {
    ($type: ident, $length_id: ident, $length: expr) => {
        pub const $length_id: usize = $length;

        #[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $type(pub [u8; $length]);

        impl $crate::hex_encoded::HexEncoded for $type {
            const LEN: usize = $length_id;

            fn inner(&mut self, index: usize) -> &mut u8 {
                &mut self.0[index]
            }
        }

        impl FromStr for $type {
            type Err = $crate::hex_encoded::ParseError;

            fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
                use $crate::hex_encoded::HexEncoded;

                Self::from_hex(&s)
            }
        }

        impl Deref for $type {
            type Target = [u8; $length_id];

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
    }
}
