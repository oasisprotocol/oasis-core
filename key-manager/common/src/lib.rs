extern crate ekiden_core;
extern crate sodalite;

extern crate serde;
#[macro_use]
extern crate serde_derive;

pub mod confidential;

use ekiden_core::bytes::{B512, H256};
use serde::de::{Deserialize, Deserializer, Error, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeTuple, Serializer};
use sodalite::*;
use std::fmt;
use std::marker::PhantomData;

/// Workaround for serializing and deserializing large arrays
/// (from https://github.com/serde-rs/serde/issues/631#issuecomment-322677033).
///
/// This is needed to properly ser/des the StateKeyType below, since by default
/// the serde library only implements ser/des for arrays up to 32 bytes.
trait BigArray<'de>: Sized {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer;
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>;
}

macro_rules! big_array {
    ($($len:expr,)+) => {
        $(
            impl<'de, T> BigArray<'de> for [T; $len]
                where T: Default + Copy + Serialize + Deserialize<'de>
            {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                    where S: Serializer
                {
                    let mut seq = serializer.serialize_tuple(self.len())?;
                    for elem in &self[..] {
                        seq.serialize_element(elem)?;
                    }
                    seq.end()
                }

                fn deserialize<D>(deserializer: D) -> Result<[T; $len], D::Error>
                    where D: Deserializer<'de>
                {
                    struct ArrayVisitor<T> {
                        element: PhantomData<T>,
                    }

                    impl<'de, T> Visitor<'de> for ArrayVisitor<T>
                        where T: Default + Copy + Deserialize<'de>
                    {
                        type Value = [T; $len];

                        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                            formatter.write_str(concat!("an array of length ", $len))
                        }

                        fn visit_seq<A>(self, mut seq: A) -> Result<[T; $len], A::Error>
                            where A: SeqAccess<'de>
                        {
                            let mut arr = [T::default(); $len];
                            for i in 0..$len {
                                arr[i] = seq.next_element()?
                                    .ok_or_else(|| Error::invalid_length(i, &self))?;
                            }
                            Ok(arr)
                        }
                    }

                    let visitor = ArrayVisitor { element: PhantomData };
                    deserializer.deserialize_tuple($len, visitor)
                }
            }
        )+
    }
}

big_array! { 64, }

/// 256-bit ContractId
pub type ContractId = H256;
/// Type of public input key
pub type PublicKeyType = BoxPublicKey;
/// Type of private input key
pub type PrivateKeyType = BoxSecretKey;
/// Type of state encryption key
pub type StateKeyType = [u8; 64];

/// Default value of a private input key
pub const EMPTY_PRIVATE_KEY: PrivateKeyType = [0; 32];
/// Default value of a public input key
pub const EMPTY_PUBLIC_KEY: PublicKeyType = [0; 32];
/// Default value of a state encryption key
pub const EMPTY_STATE_KEY: StateKeyType = [0; 64];

/// Keys for a contract
#[derive(Clone, Serialize, Deserialize)]
pub struct ContractKey {
    /// Input key pair (pk, sk)
    pub input_keypair: InputKeyPair,
    /// State encryption key
    #[serde(with = "BigArray")]
    pub state_key: StateKeyType,
}

/// Data structure returned by the key manager's `get_public_key` method.
#[derive(Clone, Debug)]
pub struct PublicKeyPayload {
    pub public_key: PublicKeyType,
    pub timestamp: u64,
    pub signature: B512,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct InputKeyPair {
    /// Pk
    pk: PublicKeyType,
    /// sk
    sk: PrivateKeyType,
}

impl InputKeyPair {
    pub fn new(pk: PublicKeyType, sk: PrivateKeyType) -> Self {
        Self { pk, sk }
    }

    pub fn get_pk(&self) -> PublicKeyType {
        self.pk
    }

    pub fn get_sk(&self) -> PrivateKeyType {
        self.sk
    }
}

impl ContractKey {
    /// Create a set of `ContractKey`.
    pub fn new(pk: PublicKeyType, sk: PrivateKeyType, k: StateKeyType) -> Self {
        Self {
            input_keypair: InputKeyPair { pk, sk },
            state_key: k,
        }
    }
    /// Create a set of `ContractKey` with only the public key.
    pub fn from_public_key(k: PublicKeyType) -> Self {
        Self {
            input_keypair: InputKeyPair {
                pk: k,
                sk: EMPTY_PRIVATE_KEY,
            },
            state_key: EMPTY_STATE_KEY,
        }
    }
}
