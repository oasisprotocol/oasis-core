use anyhow::Result;

use group::{ff::PrimeField, Group, GroupEncoding};

use super::{Error, Shareholder};

/// Cipher suite.
pub trait Suite {
    /// A prime field used for constructing the bivariate polynomial.
    type PrimeField: PrimeField;

    /// A group used for constructing the verification matrix.
    type Group: Group<Scalar = Self::PrimeField> + GroupEncoding;

    /// Maps given shareholder ID to a non-zero element of the prime field.
    fn encode_shareholder(id: Shareholder) -> Result<Self::PrimeField>;
}

/// The NIST P-384 elliptic curve group with the SHA3-384 hash function used
/// to encode arbitrary-length byte strings to elements of the underlying prime
/// field or elliptic curve points.
#[derive(Debug)]
pub struct NistP384Sha3_384;

impl Suite for NistP384Sha3_384 {
    type PrimeField = p384::Scalar;
    type Group = p384::ProjectivePoint;

    fn encode_shareholder(id: Shareholder) -> Result<Self::PrimeField> {
        let mut bytes = [0u8; 48];
        bytes[16..].copy_from_slice(&id.0);

        let s = p384::Scalar::from_slice(&bytes).or(Err(Error::ShareholderEncodingFailed))?;
        if s.is_zero().into() {
            return Err(Error::ZeroValueShareholder.into());
        }

        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, NistP384Sha3_384, Shareholder, Suite};

    #[test]
    fn test_encode() {
        let id = [0; 32];
        let zero = NistP384Sha3_384::encode_shareholder(Shareholder(id));
        assert!(zero.is_err());
        assert_eq!(
            zero.unwrap_err().to_string(),
            Error::ZeroValueShareholder.to_string()
        );

        let mut id = [0; 32];
        id[30] = 3;
        id[31] = 232;
        let thousand = NistP384Sha3_384::encode_shareholder(Shareholder(id));
        assert!(thousand.is_ok());
        assert_eq!(thousand.unwrap(), p384::Scalar::from_u64(1000));
    }
}
