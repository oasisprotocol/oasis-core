use group::ff::PrimeField;

/// Returns a vector containing powers of x: x^0, x^1, ..., x^k.
pub fn powers<Fp>(x: &Fp, k: usize) -> Vec<Fp>
where
    Fp: PrimeField,
{
    let mut pows = Vec::with_capacity(k + 1);
    let mut prev = Fp::ONE;
    for _ in 0..k {
        pows.push(prev);
        prev *= x;
    }
    pows.push(prev);
    pows
}

#[cfg(test)]
mod tests {
    use super::powers;

    #[test]
    fn test_powers() {
        let x2 = p384::Scalar::from_u64(2);
        let x4 = p384::Scalar::from_u64(4);
        let x8 = p384::Scalar::from_u64(8);
        let x16 = p384::Scalar::from_u64(16);

        let xpows = powers(&x2, 0);
        assert_eq!(xpows, vec![p384::Scalar::ONE]);

        let xpows = powers(&x2, 4);
        assert_eq!(xpows, vec![p384::Scalar::ONE, x2, x4, x8, x16]);
    }
}
