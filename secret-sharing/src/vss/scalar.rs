use group::ff::PrimeField;

/// Converts an element of a non-binary prime field to bytes.
pub fn scalar_to_bytes<Fp>(point: &Fp) -> Vec<u8>
where
    Fp: PrimeField,
{
    point.to_repr().as_ref().to_vec()
}

/// Converts bytes to an element of a non-binary prime field.
pub fn scalar_from_bytes<Fp>(bytes: &[u8]) -> Option<Fp>
where
    Fp: PrimeField,
{
    let mut repr: Fp::Repr = Default::default();
    let slice = &mut repr.as_mut()[..];

    if slice.len() != bytes.len() {
        return None;
    }

    slice.copy_from_slice(bytes);

    Fp::from_repr(repr).into()
}

#[cfg(test)]
mod tests {
    use group::ff::Field;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::vss::scalar::{scalar_from_bytes, scalar_to_bytes};

    #[test]
    fn test_serialization() {
        let rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let scalar = p384::Scalar::random(rng);
        let bytes = scalar_to_bytes(&scalar);
        let restored = scalar_from_bytes(&bytes).expect("deserialization should succeed");
        assert_eq!(scalar, restored);
    }

    #[test]
    fn test_point_from_bytes() {
        // Invalid length.
        let bytes = vec![1; 10];
        let res = scalar_from_bytes::<p384::Scalar>(&bytes);
        assert!(res.is_none());

        // Invalid value (larger than the modulus).
        let bytes = vec![255; 384 / 8];
        let res = scalar_from_bytes::<p384::Scalar>(&bytes);
        assert!(res.is_none());
    }
}
