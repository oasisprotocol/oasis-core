use anyhow::Result;

use group::{
    ff::{Field, PrimeField},
    Group, GroupEncoding,
};

use crate::churp::{Error, Shareholder};

pub mod p384;

/// Domain separation tag for encoding shareholder identifiers.
const SHAREHOLDER_ENC_DST: &[u8] = b"shareholder";

/// A trait for hashing arbitrary-length byte strings to elements of a prime field.
pub trait FieldDigest {
    /// The type representing elements of the field.
    type Output;

    /// Hashes an arbitrary-length byte string to an element of the prime field
    /// using the given message and domain separation tag.
    fn hash_to_field(msg: &[u8], dst: &[u8]) -> Result<Self::Output>;
}

/// A trait for hashing arbitrary-length byte strings to elements of a group.
pub trait GroupDigest {
    /// The type representing elements of the group.
    type Output: Group;

    /// Hashes an arbitrary-length byte string to an element of the group
    /// using the given message and domain separation tag.
    fn hash_to_group(msg: &[u8], dst: &[u8]) -> Result<Self::Output>;
}

/// A cipher suite containing a cryptographic group, along with matching field
/// and group digests.
pub trait Suite:
    FieldDigest<Output = Self::PrimeField> + GroupDigest<Output = Self::Group>
{
    /// The type representing an element modulo the order of the group.
    type PrimeField: PrimeField;

    /// The type representing an element of a cryptographic group.
    type Group: Group<Scalar = Self::PrimeField> + GroupEncoding;

    /// Encodes the given shareholder ID to a non-zero element of the prime field.
    fn encode_shareholder(id: Shareholder) -> Result<Self::PrimeField> {
        let s = Self::hash_to_field(&id.0[..], SHAREHOLDER_ENC_DST)
            .map_err(|_| Error::ShareholderEncodingFailed)?;

        if s.is_zero().into() {
            return Err(Error::ZeroValueShareholder.into());
        }

        Ok(s)
    }
}

impl<S> Suite for S
where
    S: FieldDigest + GroupDigest,
    <S as GroupDigest>::Output: Group<Scalar = <S as FieldDigest>::Output> + GroupEncoding,
{
    type PrimeField = <S as FieldDigest>::Output;
    type Group = <S as GroupDigest>::Output;
}
