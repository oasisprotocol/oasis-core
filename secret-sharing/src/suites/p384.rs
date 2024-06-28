use anyhow::Result;

use p384::{
    elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest as _},
    NistP384, ProjectivePoint, Scalar,
};

use super::{FieldDigest, GroupDigest};

/// Domain separation tag for encoding to NIST P-384 prime field or curve
/// using the SHA3-384 hash function.
const NIST_P384_SHA3_384_ENC_DST: &[u8] = b"P384_XMD:SHA3-384_SSWU_RO_";

/// The NIST P-384 elliptic curve group with the SHA3-384 hash function used
/// to encode arbitrary-length byte strings to elements of the underlying prime
/// field or elliptic curve points.
pub struct Sha3_384;

impl GroupDigest for Sha3_384 {
    type Output = ProjectivePoint;

    fn hash_to_group(msg: &[u8], dst: &[u8], identifier: &[u8]) -> Result<Self::Output> {
        let msgs = [msg];
        let dsts = [NIST_P384_SHA3_384_ENC_DST, dst, identifier];
        let p = NistP384::hash_from_bytes::<ExpandMsgXmd<sha3::Sha3_384>>(&msgs, &dsts)?;
        Ok(p)
    }
}

impl FieldDigest for Sha3_384 {
    type Output = Scalar;

    fn hash_to_field(msg: &[u8], dst: &[u8], identifier: &[u8]) -> Result<Self::Output> {
        let msgs = [msg];
        let dsts = [NIST_P384_SHA3_384_ENC_DST, dst, identifier];
        let s = NistP384::hash_to_scalar::<ExpandMsgXmd<sha3::Sha3_384>>(&msgs, &dsts)?;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    extern crate test;

    use self::test::Bencher;

    use rand::{rngs::StdRng, RngCore, SeedableRng};

    use super::{FieldDigest, GroupDigest, Sha3_384};

    #[bench]
    fn bench_hash_to_field_p384_sha3_384(b: &mut Bencher) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut data = [0; 96];

        b.iter(|| {
            rng.fill_bytes(&mut data);
            let _ = Sha3_384::hash_to_field(&data[..32], &data[32..64], &data[64..]).unwrap();
        });
    }

    #[bench]
    fn bench_hash_to_group_p384_sha3_384(b: &mut Bencher) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut data = [0; 96];

        b.iter(|| {
            rng.fill_bytes(&mut data);
            let _ = Sha3_384::hash_to_group(&data[..32], &data[32..64], &data[64..]).unwrap();
        });
    }
}
