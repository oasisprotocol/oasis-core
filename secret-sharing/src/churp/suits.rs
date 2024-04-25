use anyhow::Result;

use group::{ff::PrimeField, Group, GroupEncoding};
use p384::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};

use super::{Error, Shareholder};

/// Domain separation tag for encoding to NIST P-384 prime field or curve
/// using the SHA3-384 hash function.
const NIST_P384_SHA3_384_ENC_DST: &[u8] = b"P384_XMD:SHA3-384_SSWU_RO_";

/// Cipher suite.
pub trait Suite {
    /// A prime field used for constructing the bivariate polynomial.
    type PrimeField: PrimeField;

    /// A group used for constructing the verification matrix.
    type Group: Group<Scalar = Self::PrimeField> + GroupEncoding;

    /// Hashes an arbitrary-length byte string to an element of the prime field.
    fn hash_to_field(msg: &[u8], dst: &[u8]) -> Result<Self::PrimeField>;

    /// Hashes an arbitrary-length byte string to a point on the elliptic curve.
    fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Result<Self::Group>;

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

    fn hash_to_field(msg: &[u8], dst: &[u8]) -> Result<Self::PrimeField> {
        let msgs = [msg];
        let dsts = [NIST_P384_SHA3_384_ENC_DST, dst];
        let s = p384::NistP384::hash_to_scalar::<ExpandMsgXmd<sha3::Sha3_384>>(&msgs, &dsts)?;
        Ok(s)
    }

    fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Result<Self::Group> {
        let msgs = [msg];
        let dsts = [NIST_P384_SHA3_384_ENC_DST, dst];
        let p = p384::NistP384::hash_from_bytes::<ExpandMsgXmd<sha3::Sha3_384>>(&msgs, &dsts)?;
        Ok(p)
    }

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
    extern crate test;

    use self::test::Bencher;

    use rand::{rngs::StdRng, RngCore, SeedableRng};

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

    #[bench]
    fn bench_hash_to_field_p384_sha3_384(b: &mut Bencher) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut data = [0; 64];

        b.iter(|| {
            rng.fill_bytes(&mut data);
            let _ = NistP384Sha3_384::hash_to_field(&data[..32], &data[32..]).unwrap();
        });
    }

    #[bench]
    fn bench_hash_to_curve_p384_sha3_384(b: &mut Bencher) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut data = [0; 64];

        b.iter(|| {
            rng.fill_bytes(&mut data);
            let _ = NistP384Sha3_384::hash_to_curve(&data[..32], &data[32..]).unwrap();
        });
    }
}
