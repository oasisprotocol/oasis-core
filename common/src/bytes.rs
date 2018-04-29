//! Common bytes types.
//!
//! These represent unformatted binary data of fixed length.
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use fixed_hash::*;
use rustc_hex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{Error, SeqAccess, Visitor};

macro_rules! define_bytes_type {
    ($from: ident, $size: expr) => {
        // From fixed-hash crate.
        construct_hash!($from, $size);

        impl $from {
            /// Length constant.
            pub const LENGTH: usize = $size;

            /// Create a new, cryptographically random, instance.
            pub fn random() -> $from {
                let mut hash = $from::new();
                hash.randomize();
                hash
            }

            /// Assign self have a cryptographically random value.
            pub fn randomize(&mut self) {
                $crate::random::get_random_bytes(&mut self.0).unwrap()
            }
        }

        impl FromStr for $from {
            type Err = rustc_hex::FromHexError;

            fn from_str(s: &str) -> Result<$from, rustc_hex::FromHexError> {
                use rustc_hex::FromHex;

                let a = s.from_hex()?;
                if a.len() != $size {
                    return Err(rustc_hex::FromHexError::InvalidHexLength);
                }

                let mut ret = [0; $size];
                ret.copy_from_slice(&a);
                Ok($from(ret))
            }
        }

        impl From<&'static str> for $from {
            fn from(s: &'static str) -> $from {
                let s = clean_0x(s);
                if s.len() % 2 == 1 {
                    ("0".to_owned() + s).parse().unwrap()
                } else {
                    s.parse().unwrap()
                }
            }
        }

        impl_serialize_for_bytes!($from, $size);
        impl_deserialize_for_bytes!($from, $size);
    }
}

macro_rules! impl_serialize_for_bytes {
    ($name: ident, $size: expr) => {
        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where S: Serializer
            {
                use serde::ser::SerializeTuple;

                let mut seq = serializer.serialize_tuple($size)?;
                for e in self.0.iter() {
                    seq.serialize_element(e)?;
                }
                seq.end()
            }
        }
    }
}

macro_rules! impl_deserialize_for_bytes {
    ($name: ident, $size: expr) => {
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct ArrayVisitor<T> {
                    element: PhantomData<T>,
                }

                impl<'de, T> Visitor<'de> for ArrayVisitor<T>
                    where T: Default + Copy + Deserialize<'de>
                {
                    type Value = [T; $size];

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str(concat!("an array of length ", $size))
                    }

                    fn visit_seq<A>(self, mut seq: A) -> Result<[T; $size], A::Error>
                        where A: SeqAccess<'de>
                    {
                        let mut arr = [T::default(); $size];
                        for i in 0..$size {
                            arr[i] = seq.next_element()?
                                .ok_or_else(|| Error::invalid_length(i, &self))?;
                        }
                        Ok(arr)
                    }
                }

                let visitor = ArrayVisitor { element: PhantomData };
                Ok($name(deserializer.deserialize_tuple($size, visitor)?))
            }
        }
    }
}

// Hash types.
define_bytes_type!(H32, 4);
define_bytes_type!(H64, 8);
define_bytes_type!(H128, 16);
define_bytes_type!(H160, 20);
define_bytes_type!(H256, 32);
define_bytes_type!(H264, 33);
define_bytes_type!(H512, 64);
define_bytes_type!(H520, 65);
define_bytes_type!(H1024, 128);

// Bytes types.
define_bytes_type!(B32, 4);
define_bytes_type!(B64, 8);
define_bytes_type!(B128, 16);
define_bytes_type!(B160, 20);
define_bytes_type!(B256, 32);
define_bytes_type!(B264, 33);
define_bytes_type!(B512, 64);
define_bytes_type!(B520, 65);
define_bytes_type!(B1024, 128);

#[cfg(test)]
mod test {
    use serde_cbor;

    use super::*;

    macro_rules! define_serde_test {
        ($method:ident, $name:ident) => {
            #[test]
            fn $method() {
                let value = $name::random();
                let value_encoded = serde_cbor::to_vec(&value).unwrap();
                let value_decoded: $name = serde_cbor::from_slice(&value_encoded).unwrap();
                assert_eq!(value_decoded, value);
            }
        }
    }

    define_serde_test!(test_serde_h32, H32);
    define_serde_test!(test_serde_h64, H64);
    define_serde_test!(test_serde_h128, H128);
    define_serde_test!(test_serde_h160, H160);
    define_serde_test!(test_serde_h256, H256);
    define_serde_test!(test_serde_h264, H264);
    define_serde_test!(test_serde_h512, H512);
    define_serde_test!(test_serde_h520, H520);
    define_serde_test!(test_serde_h1024, H1024);

    define_serde_test!(test_serde_b32, B32);
    define_serde_test!(test_serde_b64, B64);
    define_serde_test!(test_serde_b128, B128);
    define_serde_test!(test_serde_b160, B160);
    define_serde_test!(test_serde_b256, B256);
    define_serde_test!(test_serde_b264, B264);
    define_serde_test!(test_serde_b512, B512);
    define_serde_test!(test_serde_b520, B520);
    define_serde_test!(test_serde_b1024, B1024);
}
