//! Common big unsigned integer types.
use std::ops::{Add, BitAnd, BitOr, BitXor, Deref, DerefMut, Div, Mul, Not, Rem, Shl, Shr, Sub};

use bigint::uint;
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

/// Implement binary operator for uint type wrapper.
macro_rules! impl_op_for_wrapper {
    ($type:ident, $op:ident, $name:ident) => {
        impl $type<$name> for $name {
            type Output = $name;

            #[inline]
            fn $op(self, other: $name) -> $name {
                $name((self.0).$op(other.0))
            }
        }
    };
}

/// Wrap given bigint::uint type so we can implement external traits on it.
macro_rules! wrap_uint_type {
    ($name:ident, $size:expr) => {
        #[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
        pub struct $name(pub uint::$name);

        impl $name {
            pub fn to_vec(&self) -> Vec<u8> {
                let mut vec = Vec::new();
                vec.resize($size, 0);
                &self.0.to_little_endian(vec.deref_mut());
                vec
            }

            pub fn from_little_endian(slice: &[u8]) -> Self {
                $name(uint::$name::from_little_endian(slice))
            }
        }

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
            uint::$name: From<T>,
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
    };
}

/// Implement `Serialize` trait for given uint type.
macro_rules! impl_serialize_for_uint {
    ($name:ident, $size:expr) => {
        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let leading_empty_bytes = $size - (self.bits() + 7) / 8;
                let mut buffer = [0u8; $size];
                self.to_big_endian(&mut buffer);
                buffer[leading_empty_bytes..].serialize(serializer)
            }
        }
    };
}

/// Implement `Deserialize` trait for given uint type.
macro_rules! impl_deserialize_for_uint {
    ($name:ident, $size:expr) => {
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let buffer: Vec<u8> = Deserialize::deserialize(deserializer)?;
                if !buffer.is_empty() && buffer[0] == 0 {
                    // Leading empty bytes should be stripped.
                    return Err(serde::de::Error::custom("incorrect uint encoding"));
                } else if buffer.len() > $size {
                    return Err(serde::de::Error::custom("incorrect uint size"));
                }

                let mut buffer_with_leading = [0u8; $size];
                buffer_with_leading[$size - buffer.len()..].copy_from_slice(&buffer);

                Ok($name::from(buffer_with_leading))
            }
        }
    };
}

// Define wrapper types so we can implement traits on them.
wrap_uint_type!(U128, 16);
wrap_uint_type!(U256, 32);

impl_serialize_for_uint!(U128, 16);
impl_serialize_for_uint!(U256, 32);

impl_deserialize_for_uint!(U128, 16);
impl_deserialize_for_uint!(U256, 32);

#[cfg(test)]
mod test {
    use serde_cbor;

    use super::*;

    macro_rules! define_serde_test {
        ($method:ident, $name:ident) => {
            #[test]
            fn $method() {
                let value = $name::from(0);
                let value_encoded = serde_cbor::to_vec(&value).unwrap();
                let value_decoded: $name = serde_cbor::from_slice(&value_encoded).unwrap();
                assert_eq!(value_decoded, value);

                let value = $name::from(1);
                let value_encoded = serde_cbor::to_vec(&value).unwrap();
                let value_decoded: $name = serde_cbor::from_slice(&value_encoded).unwrap();
                assert_eq!(value_decoded, value);

                let value = $name::from(1_234_567);
                let value_encoded = serde_cbor::to_vec(&value).unwrap();
                let value_decoded: $name = serde_cbor::from_slice(&value_encoded).unwrap();
                assert_eq!(value_decoded, value);
            }
        };
    }

    define_serde_test!(test_serde_u128, U128);
    define_serde_test!(test_serde_u256, U256);
}
