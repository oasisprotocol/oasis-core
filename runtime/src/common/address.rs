//! Consensus account address structures.
use std::fmt;

use bech32::{self, FromBase32, ToBase32};

use crate::common::{
    crypto::{hash::Hash, signature::PublicKey},
    roothash::Namespace,
};

const ADDRESS_VERSION_SIZE: usize = 1;
const ADDRESS_DATA_SIZE: usize = 20;
const ADDRESS_SIZE: usize = ADDRESS_VERSION_SIZE + ADDRESS_DATA_SIZE;

// V0 staking addres.
const ADDRESS_V0_CONTEXT: &'static [u8] = b"oasis-core/address: staking";
const ADDRESS_V0_VERSION: u8 = 0;

// V0 runtime address.
const ADDRESS_RUNTIME_V0_CONTEXT: &'static [u8] = b"oasis-core/address: runtime";
const ADDRESS_RUNTIME_V0_VERSION: u8 = 0;

const ADDRESS_BECH32_HRP: &'static str = "oasis";

/// A staking account address.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
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

    /// Converts an address to Bech32 representation.
    pub fn to_bech32(&self) -> String {
        bech32::encode(ADDRESS_BECH32_HRP, self.0.to_base32()).unwrap()
    }
}

impl fmt::LowerHex for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in &self.0[..] {
            write!(f, "{:02x}", i)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_bech32())?;
        Ok(())
    }
}

impl serde::Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        if is_human_readable {
            serializer.serialize_str(&self.to_bech32())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> serde::Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = Address;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("bytes or string expected")
            }

            fn visit_str<E>(self, data: &str) -> Result<Address, E>
            where
                E: serde::de::Error,
            {
                let (hrp, data) = bech32::decode(data)
                    .map_err(|e| serde::de::Error::custom(format!("malformed address: {}", e)))?;
                if hrp != ADDRESS_BECH32_HRP {
                    return Err(serde::de::Error::custom(format!("invalid HRP: {}", hrp)));
                }
                let data: Vec<u8> = FromBase32::from_base32(&data)
                    .map_err(|e| serde::de::Error::custom(format!("malformed address: {}", e)))?;
                if data.len() != ADDRESS_SIZE {
                    return Err(serde::de::Error::custom(format!(
                        "invalid address length: {}",
                        data.len()
                    )));
                }

                let mut a = [0; ADDRESS_SIZE];
                a.copy_from_slice(&data);
                Ok(Address(a))
            }

            fn visit_bytes<E>(self, data: &[u8]) -> Result<Address, E>
            where
                E: serde::de::Error,
            {
                if data.len() != ADDRESS_SIZE {
                    return Err(serde::de::Error::custom(format!(
                        "invalid address length: {}",
                        data.len()
                    )));
                }

                let mut a = [0; ADDRESS_SIZE];
                a.copy_from_slice(&data);
                Ok(Address(a))
            }
        }

        if deserializer.is_human_readable() {
            Ok(deserializer.deserialize_string(BytesVisitor)?)
        } else {
            Ok(deserializer.deserialize_bytes(BytesVisitor)?)
        }
    }
}

#[cfg(test)]
mod test {
    use super::Address;
    use crate::common::{crypto::signature::PublicKey, roothash::Namespace};

    #[test]
    fn test_address() {
        let pk =
            PublicKey::from("badadd1e55ffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        let addr = Address::from_pk(&pk);
        assert_eq!(
            addr.to_bech32(),
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
}
