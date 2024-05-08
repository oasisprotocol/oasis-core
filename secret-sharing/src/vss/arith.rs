use group::ff::PrimeField;

/// Returns a vector containing powers of x: x^0, x^1, ..., x^k.
pub fn powers<F: PrimeField>(x: &F, k: usize) -> Vec<F> {
    let mut pows = Vec::with_capacity(k + 1);
    let mut prev = F::ONE;
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

    type PrimeField = p384::Scalar;

    #[test]
    fn test_powers() {
        let x2 = PrimeField::from_u64(2);
        let x4 = PrimeField::from_u64(4);
        let x8 = PrimeField::from_u64(8);
        let x16 = PrimeField::from_u64(16);

        let xpows = powers(&x2, 0);
        assert_eq!(xpows, vec![PrimeField::ONE]);

        let xpows = powers(&x2, 4);
        assert_eq!(xpows, vec![PrimeField::ONE, x2, x4, x8, x16]);
    }
}
