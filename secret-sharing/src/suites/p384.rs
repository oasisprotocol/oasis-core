use anyhow::Result;

use p384::{
    elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest as _},
    NistP384, ProjectivePoint, Scalar,
};

use super::{FieldDigest, GroupDigest};

/// The NIST P-384 elliptic curve group with the SHA3-384 hash function used
/// to encode arbitrary-length byte strings to elements of the underlying prime
/// field or elliptic curve points.
pub struct Sha3_384;

impl GroupDigest for Sha3_384 {
    type Output = ProjectivePoint;

    fn hash_to_group(msg: &[u8], dst: &[u8]) -> Result<Self::Output> {
        let msgs = [msg];
        let dsts = [dst];
        let p = NistP384::hash_from_bytes::<ExpandMsgXmd<sha3::Sha3_384>>(&msgs, &dsts)?;
        Ok(p)
    }
}

impl FieldDigest for Sha3_384 {
    type Output = Scalar;

    fn hash_to_field(msg: &[u8], dst: &[u8]) -> Result<Self::Output> {
        let msgs = [msg];
        let dsts = [dst];
        let s = NistP384::hash_to_scalar::<ExpandMsgXmd<sha3::Sha3_384>>(&msgs, &dsts)?;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    extern crate test;

    use self::test::Bencher;

    use group::ff::PrimeField;
    use hex_literal::hex;
    use p384::elliptic_curve::sec1::ToEncodedPoint;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    use super::{FieldDigest, GroupDigest, Sha3_384};

    #[test]
    fn hash_to_group() {
        struct TestVector<'a> {
            msg: &'a [u8],
            dst: &'a [u8],
            point: [u8; 49],
        }

        const TEST_VECTORS: &[TestVector] = &[
            TestVector {
                msg: b"",
                dst: b"",
                point: hex!("027cf1d3ca3d2c407ea80bebe271c431491e36155bdd8c9beae0e16a3ed05638ca07039eaee720171a0d9f28ed7ef84afd"),
            },
            TestVector {
                msg: b"message",
                dst: b"",
                point: hex!("02883d74ea8eb336e4207ee7aa5243c9ab614305cfdcd4d1e6d04ec64b7520309a22073796188417d0495c70a953d1a9d2"),
            },
            TestVector {
                msg: b"",
                dst: b"domain separation tag",
                point: hex!("023ba6a657086d0c7161116e918f1e20fb4c22087428b60dc21e40d8e34d8202e7de304ad2f1464564269b28b2816694df"),
            },
            TestVector {
                msg: b"message",
                dst: b"domain separation tag",
                point: hex!("03b47f744e9e6429c2dcd1a5e86d8755e2444bb174c4abd5a94a12d241b019f8bac1d3e13956d98997f1eb554de473d8fc"),
            },
        ];

        for vector in TEST_VECTORS {
            let point = Sha3_384::hash_to_group(vector.msg, vector.dst).unwrap();
            let encoded = point.to_affine().to_encoded_point(true);
            assert_eq!(encoded.as_bytes(), vector.point);
        }
    }

    #[test]
    fn hash_to_field() {
        struct TestVector<'a> {
            msg: &'a [u8],
            dst: &'a [u8],
            point: [u8; 48],
        }

        const TEST_VECTORS: &[TestVector] = &[
            TestVector {
                msg: b"",
                dst: b"",
                point: hex!("82742bb2e0e7b910da60d384cc8da53e035d035e23db578b4e8bb4dd1d6206ae11b61db927d6ead68cda25ad22740e7b"),
            },
            TestVector {
                msg: b"message",
                dst: b"",
                point: hex!("f7822838cab288c1b6905971b34edc97f41a5adae7c2d0f081b155d2f07d2436da56c6f07f440fc2eca1d60871ba1675"),
            },
            TestVector {
                msg: b"",
                dst: b"domain separation tag",
                point: hex!("7b94116ec0559ba99feaabc4812388c6cb62ad08ee06daa40edee26a20217804dd31e9fe815a70fd2ddbd03339efac41"),
            },
            TestVector {
                msg: b"message",
                dst: b"domain separation tag",
                point: hex!("e82aee1e13464f320c4d58e7fbb266efbe47f48691bf09221c8a816da54911c367267d046b386b11526e62af2ac49c12"),
            },
        ];

        for vector in TEST_VECTORS {
            let scalar = Sha3_384::hash_to_field(vector.msg, vector.dst).unwrap();
            let encoded = scalar.to_repr();
            assert_eq!(encoded.as_slice(), vector.point);
        }
    }

    #[bench]
    fn bench_hash_to_field_p384_sha3_384(b: &mut Bencher) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut data = [0; 64];

        b.iter(|| {
            rng.fill_bytes(&mut data);
            let _ = Sha3_384::hash_to_field(&data[..32], &data[32..64]).unwrap();
        });
    }

    #[bench]
    fn bench_hash_to_group_p384_sha3_384(b: &mut Bencher) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut data = [0; 64];

        b.iter(|| {
            rng.fill_bytes(&mut data);
            let _ = Sha3_384::hash_to_group(&data[..32], &data[32..64]).unwrap();
        });
    }
}
