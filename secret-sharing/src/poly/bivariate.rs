use group::ff::PrimeField;
use rand_core::RngCore;
use subtle::{Choice, CtOption};
use zeroize::Zeroize;

use crate::poly::powers;

use super::Polynomial;

/// Bivariate polynomial over a non-binary prime field.
///
/// ```text
/// B(x,y) = \sum_{i=0}^{deg_x} \sum_{j=0}^{deg_y} b_{i,j} x^i y^j
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct BivariatePolynomial<F: PrimeField> {
    /// The degree of the bivariate polynomial in the x variable.
    pub deg_x: usize,
    /// The degree of the bivariate polynomial in the y variable.
    pub deg_y: usize,
    /// The coefficients of the bivariate polynomial, where `b[i][j]`
    /// represents the coefficient of the term `x^i y^j`.
    pub b: Vec<Vec<F>>,
}

impl<F> BivariatePolynomial<F>
where
    F: PrimeField,
{
    /// Creates a bivariate polynomial initialized to zero.
    pub fn zero(deg_x: u8, deg_y: u8) -> Self {
        let deg_x = deg_x as usize;
        let deg_y = deg_y as usize;

        let b = vec![vec![F::ZERO; deg_y + 1]; deg_x + 1];
        Self { b, deg_x, deg_y }
    }

    /// Creates a bivariate polynomial with random coefficients.
    ///
    /// This method is not constant time as some prime field implementations
    /// may generate uniformly random elements using rejection sampling.
    pub fn random(deg_x: u8, deg_y: u8, rng: &mut impl RngCore) -> Self {
        let deg_x = deg_x as usize;
        let deg_y = deg_y as usize;

        let mut b = Vec::with_capacity(deg_x + 1);
        for _ in 0..b.capacity() {
            let mut bi = Vec::with_capacity(deg_y + 1);
            for _ in 0..bi.capacity() {
                let bij = F::random(&mut *rng);
                bi.push(bij);
            }
            b.push(bi);
        }

        Self { b, deg_x, deg_y }
    }

    /// Creates a bivariate polynomial with the given coefficients.
    ///
    /// # Panics
    ///
    /// Panics, if the polynomial is invalid.
    pub fn with_coefficients(b: Vec<Vec<F>>) -> Self {
        if b.is_empty() {
            return Self::zero(0, 0);
        }

        let len = b[0].len();
        for bi in b.iter() {
            if bi.len() != len || bi.is_empty() {
                panic!("invalid polynomial");
            }
        }

        let deg_x = b.len() - 1;
        let deg_y = b[0].len() - 1;

        Self { b, deg_x, deg_y }
    }

    /// Sets the coefficient `b_{i,j}` that belongs to the term `x^i y^j`.
    ///
    /// If the coefficient does not exist, this is a no-op.
    pub fn set_coefficient(&mut self, i: usize, j: usize, bij: F) -> bool {
        if let Some(bi) = self.b.get_mut(i) {
            if let Some(old_bij) = bi.get_mut(j) {
                *old_bij = bij;
                return true;
            }
        }
        false
    }

    /// Sets the coefficient `b_{0,0}` of the constant term to zero,
    /// effectively creating a zero-hole bivariate polynomial.
    pub fn to_zero_hole(&mut self) {
        let updated = self.set_coefficient(0, 0, F::ZERO);
        debug_assert!(updated);
    }

    /// Returns true iff the coefficient `b_{0,0}` of the constant term is zero.
    pub fn is_zero_hole(&self) -> bool {
        self.b[0][0].is_zero().into()
    }

    /// Returns the coefficient `b_{i,j}` of the bivariate polynomial.
    pub fn coefficient(&self, i: usize, j: usize) -> Option<&F> {
        self.b.get(i).and_then(|bi| bi.get(j))
    }

    /// Returns the byte representation of the bivariate polynomial.
    pub fn to_bytes(&self) -> Vec<u8> {
        let cap = Self::byte_size(self.deg_x, self.deg_y);
        let mut bytes = Vec::with_capacity(cap);
        bytes.extend([self.deg_x as u8, self.deg_y as u8].iter());
        for bi in &self.b {
            for bij in bi {
                bytes.extend_from_slice(bij.to_repr().as_ref());
            }
        }

        bytes
    }

    /// Attempts to create a bivariate polynomial from its byte representation.
    ///
    /// This method is not constant time if the length of the slice is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        // Short-circuit on the length of the slice, not its contents.
        if bytes.len() < 2 {
            return None;
        }

        let deg_x = bytes[0] as usize;
        let deg_y = bytes[1] as usize;
        let expected_len = Self::byte_size(deg_x, deg_y);

        if bytes.len() != expected_len {
            return None;
        }

        // Don't short-circuit this loop to avoid revealing which coefficient
        // failed to decode.
        let coefficient_size = Self::coefficient_byte_size();
        let mut b = Vec::with_capacity(deg_x + 1);
        let mut failed = Choice::from(0);

        for chunks in bytes[2..].chunks(coefficient_size * (deg_y + 1)) {
            let mut bi = Vec::with_capacity(deg_y + 1);

            for chunk in chunks.chunks(coefficient_size) {
                let mut repr: F::Repr = Default::default();
                repr.as_mut().copy_from_slice(chunk);

                let maybe_bij = F::from_repr(repr);
                failed |= maybe_bij.is_none();

                let bij = maybe_bij.unwrap_or(Default::default());
                bi.push(bij);
            }

            b.push(bi)
        }

        let bp = Self::with_coefficients(b);
        let res = CtOption::new(bp, !failed);

        res.into()
    }

    /// Returns the size of the byte representation of a coefficient.
    pub const fn coefficient_byte_size() -> usize {
        F::NUM_BITS.saturating_add(7) as usize / 8
    }

    /// Returns the size of the byte representation of the bivariate polynomial.
    pub const fn byte_size(deg_x: usize, deg_y: usize) -> usize {
        2 + (deg_x + 1) * (deg_y + 1) * Self::coefficient_byte_size()
    }

    /// Evaluates the bivariate polynomial.
    pub fn eval(&self, x: &F, y: &F) -> F {
        let xpows = powers(x, self.deg_x); // [x^i]
        let ypows = powers(y, self.deg_y); // [y^j]
        let mut v = F::ZERO;
        for (i, xpow) in xpows.iter().enumerate() {
            let mut vi = F::ZERO;
            for (j, ypow) in ypows.iter().enumerate() {
                vi += self.b[i][j] * ypow //  b_{i,j} y^j
            }
            v += vi * xpow // \sum_{j=0}^{deg_y} b_{i,j} x^i y^j
        }

        v
    }

    /// Evaluates the bivariate polynomial with respect to the indeterminate x.
    ///
    /// Returned polynomial:
    /// ```text
    /// A(y) = \sum_{j=0}^{deg_y} a_j y^j
    /// ```
    /// where
    /// ```text
    /// a_j = \sum_{i=0}^{deg_x} b_{i,j} x^i
    /// ```
    pub fn eval_x(&self, x: &F) -> Polynomial<F> {
        let xpows = powers(x, self.deg_x); // [x^i]
        let mut a = Vec::with_capacity(self.deg_y + 1);
        for j in 0..=self.deg_y {
            let mut aj = F::ZERO;
            for (i, xpow) in xpows.iter().enumerate() {
                aj += self.b[i][j] * xpow //  b_{i,j} x^i
            }
            a.push(aj)
        }

        Polynomial::with_coefficients(a)
    }

    /// Evaluates the bivariate polynomial with respect to the indeterminate y.
    ///
    /// Returned polynomial:
    /// ```text
    /// A(x) = \sum_{i=0}^{deg_x} a_i x^i
    /// ```
    /// where
    /// ```text
    /// a_i = \sum_{j=0}^{deg_y} b_{i,j} y^j
    /// ```
    pub fn eval_y(&self, y: &F) -> Polynomial<F> {
        let ypows = powers(y, self.deg_y); // [y^j]
        let mut a = Vec::with_capacity(self.deg_x + 1);
        for i in 0..=self.deg_x {
            let mut ai = F::ZERO;
            for (j, ypow) in ypows.iter().enumerate() {
                ai += self.b[i][j] * ypow // b_{i,j} y^j
            }
            a.push(ai)
        }

        Polynomial::with_coefficients(a)
    }
}

impl<F> Zeroize for BivariatePolynomial<F>
where
    F: PrimeField + Zeroize,
{
    fn zeroize(&mut self) {
        for bi in self.b.iter_mut() {
            for bij in bi.iter_mut() {
                bij.zeroize();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic;

    use rand::{rngs::StdRng, SeedableRng};

    type PrimeField = p384::Scalar;
    type Polynomial = super::Polynomial<PrimeField>;
    type BivariatePolynomial = super::BivariatePolynomial<PrimeField>;

    fn scalar(value: i64) -> PrimeField {
        scalars(&vec![value])[0]
    }

    fn scalars(values: &[i64]) -> Vec<PrimeField> {
        values
            .iter()
            .map(|&w| match w.is_negative() {
                false => PrimeField::from_u64(w as u64),
                true => PrimeField::from_u64(-w as u64).neg(),
            })
            .collect()
    }

    #[test]
    fn test_zero() {
        let bp = BivariatePolynomial::zero(0, 0);
        assert_eq!(bp.deg_x, 0);
        assert_eq!(bp.deg_y, 0);
        assert_eq!(bp.b.len(), 1);
        assert_eq!(bp.b[0].len(), 1);
        assert_eq!(bp.b[0][0], scalar(0));

        let bp = BivariatePolynomial::zero(2, 3);
        assert_eq!(bp.deg_x, 2);
        assert_eq!(bp.deg_y, 3);
        assert_eq!(bp.b.len(), 3);
        for bi in bp.b.iter() {
            assert_eq!(bi.len(), 4);
            for bij in bi.iter() {
                assert_eq!(bij, &scalar(0));
            }
        }
    }

    #[test]
    fn test_with_coefficients() {
        let b = vec![scalars(&[1, 2, 3]), scalars(&[2, 3, 1])];

        let bp = BivariatePolynomial::with_coefficients(vec![]);
        assert_eq!(bp.deg_x, 0);
        assert_eq!(bp.deg_y, 0);
        assert_eq!(bp.b, vec![scalars(&[0])]);

        let bp = BivariatePolynomial::with_coefficients(b.clone());
        assert_eq!(bp.deg_x, 1);
        assert_eq!(bp.deg_y, 2);
        assert_eq!(bp.b, b);

        let result = panic::catch_unwind(|| {
            _ = BivariatePolynomial::with_coefficients(vec![vec![]]);
        });
        assert!(result.is_err());

        let result = panic::catch_unwind(|| {
            _ = BivariatePolynomial::with_coefficients(vec![scalars(&[1, 2]), scalars(&[1])]);
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_random() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let bp = BivariatePolynomial::random(0, 0, &mut rng);
        assert_eq!(bp.deg_x, 0);
        assert_eq!(bp.deg_y, 0);
        assert_eq!(bp.b.len(), 1);
        assert_eq!(bp.b[0].len(), 1);
        assert_ne!(bp.b[0][0], scalar(0)); // Zero with negligible probability.

        let bp = BivariatePolynomial::random(2, 3, &mut rng);
        assert_eq!(bp.deg_x, 2);
        assert_eq!(bp.deg_y, 3);
        assert_eq!(bp.b.len(), 3);
        for bi in bp.b.iter() {
            assert_eq!(bi.len(), 4);
            for bij in bi.iter() {
                assert_ne!(bij, &scalar(0)); // Zero with negligible probability.
            }
        }
    }

    #[test]
    fn test_set_coefficient() {
        let mut bp = BivariatePolynomial::zero(2, 3);
        assert_eq!(bp.b[0][0], scalar(0));

        assert!(bp.set_coefficient(0, 0, scalar(1)));
        assert_eq!(bp.b[0][0], scalar(1));
    }

    #[test]
    fn test_to_zero_hole() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut bp = BivariatePolynomial::random(2, 3, &mut rng);

        assert!(bp.set_coefficient(0, 0, scalar(1)));
        assert_eq!(bp.b[0][0], scalar(1));

        bp.to_zero_hole();
        assert_eq!(bp.b[0][0], scalar(0));
    }

    #[test]
    fn test_is_zero_hole() {
        // The constant term is 1.
        let b = vec![scalars(&[1, 2, 3]), scalars(&[2, 3, 1])];
        let mut bp = BivariatePolynomial::with_coefficients(b);
        assert!(!bp.is_zero_hole());

        // The constant term is 0.
        bp.to_zero_hole();
        assert!(bp.is_zero_hole());
    }

    #[test]
    fn test_coefficient() {
        let b = vec![scalars(&[1, 2, 3]), scalars(&[2, 3, 1])];
        let bp = BivariatePolynomial::with_coefficients(b.clone());

        // Test coefficients within bounds.
        for i in 0..b.len() {
            for j in 0..b[i].len() {
                assert_eq!(bp.coefficient(i, j), Some(&b[i][j]));
            }
        }

        // Test coefficients out of bounds.
        assert_eq!(bp.coefficient(0, 3), None);
        assert_eq!(bp.coefficient(2, 0), None);
    }

    #[test]
    fn test_serialization() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let bp = BivariatePolynomial::random(0, 0, &mut rng);
        let restored = BivariatePolynomial::from_bytes(&bp.to_bytes())
            .expect("deserialization should succeed");
        assert!(bp == restored);

        let bp = BivariatePolynomial::random(2, 3, &mut rng);
        let restored = BivariatePolynomial::from_bytes(&bp.to_bytes())
            .expect("deserialization should succeed");
        assert!(bp == restored);
    }

    #[test]
    fn test_coefficient_byte_size() {
        let size = BivariatePolynomial::coefficient_byte_size();
        assert_eq!(size, 48);
    }

    #[test]
    fn test_byte_size() {
        let size = BivariatePolynomial::byte_size(2, 3);
        assert_eq!(size, 2 + 3 * 4 * 48);
    }

    #[test]
    fn test_eval() {
        let b = vec![scalars(&[1])];
        let bp = BivariatePolynomial::with_coefficients(b);

        let result = bp.eval(&scalar(5), &scalar(2));
        let expected = scalar(1);
        assert_eq!(result, expected);

        let result = bp.eval_x(&scalar(5));
        let expected = Polynomial::with_coefficients(scalars(&[1]));
        assert!(result == expected);

        let result = bp.eval_y(&scalar(5));
        let expected = Polynomial::with_coefficients(scalars(&[1]));
        assert!(result == expected);

        let b = vec![
            scalars(&[1, 2, 3, 4]),
            scalars(&[2, 3, 4, 1]),
            scalars(&[3, 4, 1, 2]),
        ];
        let bp = BivariatePolynomial::with_coefficients(b);

        let result = bp.eval(&scalar(5), &scalar(2));
        let expected = scalar(984);
        assert_eq!(result, expected);

        let result = bp.eval_x(&scalar(5));
        let expected = Polynomial::with_coefficients(scalars(&[86, 117, 48, 59]));
        assert!(result == expected);

        let result = bp.eval_y(&scalar(5));
        let expected = Polynomial::with_coefficients(scalars(&[586, 242, 298]));
        assert!(result == expected);
    }
}
