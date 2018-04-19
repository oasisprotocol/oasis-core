//! Common hash types.
//!
//! These represent unformatted binary data of fixed length.
use std::cmp;
use std::str::FromStr;

use fixed_hash::*;
use rlp::{Decodable, DecoderError, Encodable, RlpStream, UntrustedRlp};
use rustc_hex;

macro_rules! define_hash_type {
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

        impl_encodable_for_hash!($from);
        impl_decodable_for_hash!($from, $size);
    }
}

macro_rules! impl_encodable_for_hash {
    ($name: ident) => {
        impl Encodable for $name {
            fn rlp_append(&self, stream: &mut RlpStream) {
                stream.encoder().encode_value(self);
            }
        }
    }
}

macro_rules! impl_decodable_for_hash {
    ($name: ident, $size: expr) => {
        impl Decodable for $name {
            fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
                rlp.decoder().decode_value(|bytes| match bytes.len().cmp(&$size) {
                    cmp::Ordering::Less => Err(DecoderError::RlpIsTooShort),
                    cmp::Ordering::Greater => Err(DecoderError::RlpIsTooBig),
                    cmp::Ordering::Equal => {
                        let mut dst = [0u8; $size];
                        dst.copy_from_slice(bytes);
                        Ok($name(dst))
                    }
                })
            }
        }
    }
}

// Hash types.
define_hash_type!(H32, 4);
define_hash_type!(H64, 8);
define_hash_type!(H128, 16);
define_hash_type!(H160, 20);
define_hash_type!(H256, 32);
define_hash_type!(H264, 33);
define_hash_type!(H512, 64);
define_hash_type!(H520, 65);
define_hash_type!(H1024, 128);

// Bytes types.
define_hash_type!(B32, 4);
define_hash_type!(B64, 8);
define_hash_type!(B128, 16);
define_hash_type!(B160, 20);
define_hash_type!(B256, 32);
define_hash_type!(B264, 33);
define_hash_type!(B512, 64);
define_hash_type!(B520, 65);
define_hash_type!(B1024, 128);
