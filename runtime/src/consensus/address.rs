//! Consensus account address structures.
use std::{convert::TryInto, fmt};

use anyhow::{anyhow, Result};
use bech32::{Bech32, Hrp};
use lazy_static::lazy_static;

use crate::common::{
    crypto::{hash::Hash, signature::PublicKey},
    key_format::KeyFormatAtom,
    namespace::Namespace,
};

lazy_static! {
    /// Common pool reserved address.
    pub static ref COMMON_POOL_ADDRESS: Address = Address::from_pk(&PublicKey::from("1abe11edc001ffffffffffffffffffffffffffffffffffffffffffffffffffff"));

    /// Per-block fee accumulator reserved address.
    pub static ref FEE_ACC_ADDRESS: Address = Address::from_pk(&PublicKey::from("1abe11edfeeaccffffffffffffffffffffffffffffffffffffffffffffffffff"));

    /// Governance deposits reserved address.
    pub static ref GOVERNANCE_DEPOSITS_ADDRESS: Address = Address::from_pk(&PublicKey::from("1abe11eddeaccfffffffffffffffffffffffffffffffffffffffffffffffffff"));
}

const ADDRESS_VERSION_SIZE: usize = 1;
const ADDRESS_DATA_SIZE: usize = 20;
const ADDRESS_SIZE: usize = ADDRESS_VERSION_SIZE + ADDRESS_DATA_SIZE;

// V0 staking addres.
const ADDRESS_V0_CONTEXT: &[u8] = b"oasis-core/address: staking";
const ADDRESS_V0_VERSION: u8 = 0;

// V0 runtime address.
const ADDRESS_RUNTIME_V0_CONTEXT: &[u8] = b"oasis-core/address: runtime";
const ADDRESS_RUNTIME_V0_VERSION: u8 = 0;

const ADDRESS_BECH32_HRP: Hrp = Hrp::parse_unchecked("oasis");

/// A staking account address.
#[derive(Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address([u8; ADDRESS_SIZE]);

impl Address {
    /// Creates a new address from a context, version and data.
    pub fn new(ctx: &'static [u8], version: u8, data: &[u8]) -> Self {
        let h = Hash::digest_bytes_list(&[ctx, &[version], data]);

        let mut a = [0; ADDRESS_SIZE];
        a[..ADDRESS_VERSION_SIZE].copy_from_slice(&[version]);
        a[ADDRESS_VERSION_SIZE..].copy_from_slice(h.truncated(ADDRESS_DATA_SIZE));

        Address(a)
    }

    /// Creates a new address from a public key.
    pub fn from_pk(pk: &PublicKey) -> Self {
        Address::new(ADDRESS_V0_CONTEXT, ADDRESS_V0_VERSION, pk.as_ref())
    }

    /// Creates a new runtime address.
    pub fn from_runtime_id(id: &Namespace) -> Self {
        Address::new(
            ADDRESS_RUNTIME_V0_CONTEXT,
            ADDRESS_RUNTIME_V0_VERSION,
            id.as_ref(),
        )
    }

    /// Tries to create a new address from Bech32-encoded string.
    pub fn from_bech32(data: &str) -> Result<Self> {
        let (hrp, data) = bech32::decode(data).map_err(|_| anyhow!("malformed address"))?;

        if hrp != ADDRESS_BECH32_HRP {
            return Err(anyhow!("malformed address"));
        }

        let sized: &[u8; ADDRESS_SIZE] = &data.as_slice().try_into()?;
        Ok(sized.into())
    }

    /// Converts an address to Bech32 representation.
    pub fn to_bech32(&self) -> String {
        bech32::encode::<Bech32>(ADDRESS_BECH32_HRP, &self.0).unwrap()
    }
}

impl fmt::LowerHex for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in &self.0[..] {
            write!(f, "{i:02x}")?;
        }
        Ok(())
    }
}

impl<'a> From<&'a str> for Address {
    fn from(s: &'a str) -> Address {
        Address::from_bech32(s).unwrap()
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Address> for [u8; ADDRESS_SIZE] {
    fn from(val: Address) -> Self {
        val.0
    }
}

impl From<&[u8; ADDRESS_SIZE]> for Address {
    fn from(b: &[u8; ADDRESS_SIZE]) -> Address {
        let mut data = [0; ADDRESS_SIZE];
        data.copy_from_slice(b);
        Address(data)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_bech32())?;
        Ok(())
    }
}

impl cbor::Encode for Address {
    fn into_cbor_value(self) -> cbor::Value {
        cbor::Value::ByteString(self.as_ref().to_vec())
    }
}

impl cbor::Decode for Address {
    fn try_default() -> Result<Self, cbor::DecodeError> {
        Ok(Default::default())
    }

    fn try_from_cbor_value(value: cbor::Value) -> Result<Self, cbor::DecodeError> {
        match value {
            cbor::Value::ByteString(data) => Ok(Address(
                data.try_into()
                    .map_err(|_| cbor::DecodeError::UnexpectedType)?,
            )),
            _ => Err(cbor::DecodeError::UnexpectedType),
        }
    }
}

impl KeyFormatAtom for Address {
    fn size() -> usize {
        ADDRESS_SIZE
    }

    fn encode_atom(self) -> Vec<u8> {
        self.as_ref().to_vec()
    }

    fn decode_atom(data: &[u8]) -> Self
    where
        Self: Sized,
    {
        let sized: &[u8; ADDRESS_SIZE] =
            &data.try_into().expect("address: invalid decode atom data");
        sized.into()
    }
}

#[cfg(test)]
mod test {
    use super::Address;
    use crate::common::{crypto::signature::PublicKey, namespace::Namespace};

    #[test]
    fn test_address() {
        let pk =
            PublicKey::from("badadd1e55ffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        let addr = Address::from_pk(&pk);
        assert_eq!(
            addr.to_bech32(),
            "oasis1qryqqccycvckcxp453tflalujvlf78xymcdqw4vz"
        );

        assert_eq!(
            Address::from("oasis1qryqqccycvckcxp453tflalujvlf78xymcdqw4vz").to_bech32(),
            "oasis1qryqqccycvckcxp453tflalujvlf78xymcdqw4vz"
        );

        let runtime_id =
            Namespace::from("80000000000000002aff7f6dfb62720cfd735f2b037b81572fad1b7937d826b3");
        let addr = Address::from_runtime_id(&runtime_id);
        assert_eq!(
            addr.to_bech32(),
            "oasis1qpllh99nhwzrd56px4txvl26atzgg4f3a58jzzad"
        );
    }

    #[test]
    fn test_deserialization() {
        let addr: Address = cbor::from_slice(&[0xF6]).unwrap();
        assert_eq!(
            addr.to_bech32(),
            "oasis1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0ltrq9"
        );
    }
}
