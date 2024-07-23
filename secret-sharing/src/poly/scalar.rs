use group::ff::PrimeField;

/// Converts an element of a non-binary prime field to bytes.
pub fn scalar_to_bytes<F: PrimeField>(element: &F) -> Vec<u8> {
    element.to_repr().as_ref().to_vec()
}

/// Converts bytes to an element of a non-binary prime field.
pub fn scalar_from_bytes<F: PrimeField>(bytes: &[u8]) -> Option<F> {
    let mut repr: F::Repr = Default::default();
    let slice = &mut repr.as_mut()[..];

    if slice.len() != bytes.len() {
        return None;
    }

    slice.copy_from_slice(bytes);

    F::from_repr(repr).into()
}

#[cfg(test)]
mod tests {
    use group::ff::Field;
    use rand::{rngs::StdRng, SeedableRng};

    use super::{scalar_from_bytes, scalar_to_bytes};

    type PrimeField = p384::Scalar;

    #[test]
    fn test_serialization() {
        let rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let scalar = PrimeField::random(rng);
        let bytes = scalar_to_bytes(&scalar);
        let restored = scalar_from_bytes(&bytes).expect("deserialization should succeed");
        assert_eq!(scalar, restored);
    }

    #[test]
    fn test_point_from_bytes() {
        // Invalid length.
        let bytes = vec![1; 10];
        let res = scalar_from_bytes::<PrimeField>(&bytes);
        assert!(res.is_none());

        // Invalid value (larger than the modulus).
        let bytes = vec![255; 384 / 8];
        let res = scalar_from_bytes::<PrimeField>(&bytes);
        assert!(res.is_none());
    }
}
