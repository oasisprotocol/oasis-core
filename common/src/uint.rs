//! Common big unsigned integer types.
use std::ops::{Add, BitAnd, BitOr, BitXor, Deref, DerefMut, Div, Mul, Not, Rem, Shl, Shr, Sub};

use bigint::uint;
use rlp::{Decodable, DecoderError, Encodable, RlpStream, UntrustedRlp};

/// Implement binary operator for uint type wrapper.
macro_rules! impl_op_for_wrapper {
    ($type: ident, $op: ident, $name: ident) => {
        impl $type<$name> for $name {
            type Output = $name;

            #[inline]
            fn $op(self, other: $name) -> $name {
                $name((self.0).$op(other.0))
            }
        }
    }
}

/// Wrap given bigint::uint type so we can implement external traits on it.
macro_rules! wrap_uint_type {
    ($name: ident) => {
        #[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
        pub struct $name(pub uint::$name);

        impl Deref for $name {
            type Target = uint::$name;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl<T> From<T> for $name
        where
            uint::$name: From<T>
        {
            fn from(value: T) -> Self {
                $name(value.into())
            }
        }

        impl_op_for_wrapper!(Add, add, $name);
        impl_op_for_wrapper!(Sub, sub, $name);
        impl_op_for_wrapper!(Mul, mul, $name);
        impl_op_for_wrapper!(Div, div, $name);
        impl_op_for_wrapper!(Rem, rem, $name);
        impl_op_for_wrapper!(BitAnd, bitand, $name);
        impl_op_for_wrapper!(BitXor, bitxor, $name);
        impl_op_for_wrapper!(BitOr, bitor, $name);

        impl Not for $name {
            type Output = $name;

            #[inline]
            fn not(self) -> $name {
                $name(self.0.not())
            }
        }

        impl Shl<usize> for $name {
            type Output = $name;

            fn shl(self, shift: usize) -> $name {
                $name(self.0.shl(shift))
            }
        }

        impl Shr<usize> for $name {
            type Output = $name;

            fn shr(self, shift: usize) -> $name {
                $name(self.0.shr(shift))
            }
        }
    }
}

/// Implement `Encodable` trait for given uint type.
macro_rules! impl_encodable_for_uint {
    ($name: ident, $size: expr) => {
        impl Encodable for $name {
            fn rlp_append(&self, s: &mut RlpStream) {
                let leading_empty_bytes = $size - (self.bits() + 7) / 8;
                let mut buffer = [0u8; $size];
                self.to_big_endian(&mut buffer);
                s.encoder().encode_value(&buffer[leading_empty_bytes..]);
            }
        }
    }
}

/// Implement `Decodable` trait for given uint type.
macro_rules! impl_decodable_for_uint {
    ($name: ident, $size: expr) => {
        impl Decodable for $name {
            fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
                rlp.decoder().decode_value(|bytes| {
                    if !bytes.is_empty() && bytes[0] == 0 {
                        Err(DecoderError::RlpInvalidIndirection)
                    } else if bytes.len() <= $size {
                        Ok($name::from(bytes))
                    } else {
                        Err(DecoderError::RlpIsTooBig)
                    }
                })
            }
        }
    }
}

// Define wrapper types so we can implement traits on them.
wrap_uint_type!(U128);
wrap_uint_type!(U256);

impl_encodable_for_uint!(U128, 16);
impl_encodable_for_uint!(U256, 32);

impl_decodable_for_uint!(U128, 16);
impl_decodable_for_uint!(U256, 32);
