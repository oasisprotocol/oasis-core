use group::ff::PrimeField;
use rand_core::RngCore;

use crate::vss::arith::powers;

use super::Polynomial;

/// Bivariate polynomial over a non-binary prime field.
///
/// ```text
/// B(x,y) = \sum_{i=0}^{deg_x} \sum_{j=0}^{deg_y} b_{i,j} x^i y^j
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct BivariatePolynomial<Fp>
where
    Fp: PrimeField,
{
    /// The degree of the bivariate polynomial in the x variable.
    pub deg_x: usize,
    /// The degree of the bivariate polynomial in the y variable.
    pub deg_y: usize,
    /// The coefficients of the bivariate polynomial, where `b[i][j]`
    /// represents the coefficient of the term `x^i y^j`.
    pub b: Vec<Vec<Fp>>,
}

impl<Fp> BivariatePolynomial<Fp>
where
    Fp: PrimeField,
{
    /// Creates a bivariate polynomial initialized to zero.
    pub fn zero(deg_x: u8, deg_y: u8) -> Self {
        let deg_x = deg_x as usize;
        let deg_y = deg_y as usize;

        let b = vec![vec![Fp::ZERO; deg_y + 1]; deg_x + 1];
        Self { b, deg_x, deg_y }
    }

    /// Creates a bivariate polynomial with random coefficients.
    pub fn random(deg_x: u8, deg_y: u8, rng: &mut impl RngCore) -> Self {
        let deg_x = deg_x as usize;
        let deg_y = deg_y as usize;

        let mut b = Vec::with_capacity(deg_x + 1);
        for _ in 0..b.capacity() {
            let mut bi = Vec::with_capacity(deg_y + 1);
            for _ in 0..bi.capacity() {
                let bij = Fp::random(&mut *rng);
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
    pub fn with_coefficients(b: Vec<Vec<Fp>>) -> Self {
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
    pub fn set_coefficient(&mut self, bij: Fp, i: usize, j: usize) {
        if let Some(bi) = self.b.get_mut(i) {
            if let Some(old_bij) = bi.get_mut(j) {
                *old_bij = bij;
            }
        }
    }

    /// Sets the coefficient `b_{0,0}` of the constant term to zero,
    /// effectively creating a zero-hole bivariate polynomial.
    pub fn to_zero_hole(&mut self) {
        self.set_coefficient(Fp::ZERO, 0, 0);
    }

    /// Returns true if and only if the coefficient `b_{0,0}` of the constant
    /// term is zero.
    pub fn is_zero_hole(&self) -> bool {
        self.b[0][0].is_zero().into()
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
    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }

        let deg_x = bytes[0] as usize;
        let deg_y = bytes[1] as usize;

        if bytes.len() != Self::byte_size(deg_x, deg_y) {
            return None;
        }

        let mut bytes = &bytes[2..];
        let mut b = Vec::with_capacity(deg_x + 1);
        for _ in 0..=deg_x {
            let mut bi = Vec::with_capacity(deg_y + 1);
            for _ in 0..=deg_y {
                let mut repr: Fp::Repr = Default::default();
                let slice = &mut repr.as_mut()[..];
                let (bij, rest) = bytes.split_at(slice.len());
                slice.copy_from_slice(bij);
                bytes = rest;

                let bij = match Fp::from_repr(repr).into() {
                    None => return None,
                    Some(bij) => bij,
                };

                bi.push(bij);
            }
            b.push(bi);
        }

        Some(Self { deg_x, deg_y, b })
    }

    /// Returns the size of the byte representation of a coefficient.
    pub fn coefficient_byte_size() -> usize {
        Fp::NUM_BITS.saturating_add(7) as usize / 8
    }

    /// Returns the size of the byte representation of the bivariate polynomial.
    pub fn byte_size(deg_x: usize, deg_y: usize) -> usize {
        2 + (deg_x + 1) * (deg_y + 1) * Self::coefficient_byte_size()
    }

    /// Evaluates the bivariate polynomial.
    pub fn eval(&self, x: &Fp, y: &Fp) -> Fp {
        let xpows = powers(x, self.deg_x); // [x^i]
        let ypows = powers(y, self.deg_y); // [y^j]
        let mut v = Fp::ZERO;
        for (i, xpow) in xpows.iter().enumerate() {
            let mut vi = Fp::ZERO;
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
    pub fn eval_x(&self, x: &Fp) -> Polynomial<Fp> {
        let xpows = powers(x, self.deg_x); // [x^i]
        let mut a = Vec::with_capacity(self.deg_y + 1);
        for j in 0..=self.deg_y {
            let mut aj = Fp::ZERO;
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
    pub fn eval_y(&self, y: &Fp) -> Polynomial<Fp> {
        let ypows = powers(y, self.deg_y); // [y^j]
        let mut a = Vec::with_capacity(self.deg_x + 1);
        for i in 0..=self.deg_x {
            let mut ai = Fp::ZERO;
            for (j, ypow) in ypows.iter().enumerate() {
                ai += self.b[i][j] * ypow // b_{i,j} y^j
            }
            a.push(ai)
        }

        Polynomial::with_coefficients(a)
    }
}

#[cfg(test)]
mod tests {
    use std::panic;

    use rand::{rngs::StdRng, SeedableRng};

    use super::{BivariatePolynomial, Polynomial};

    fn scalar(value: i64) -> p384::Scalar {
        scalars(&vec![value])[0]
    }

    fn scalars(values: &[i64]) -> Vec<p384::Scalar> {
        values
            .iter()
            .map(|&w| match w.is_negative() {
                false => p384::Scalar::from_u64(w as u64),
                true => p384::Scalar::from_u64(-w as u64).neg(),
            })
            .collect()
    }

    #[test]
    fn test_zero() {
        let bp = BivariatePolynomial::<p384::Scalar>::zero(0, 0);
        assert_eq!(bp.deg_x, 0);
        assert_eq!(bp.deg_y, 0);
        assert_eq!(bp.b.len(), 1);
        assert_eq!(bp.b[0].len(), 1);
        assert_eq!(bp.b[0][0], scalar(0));

        let bp = BivariatePolynomial::<p384::Scalar>::zero(2, 3);
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

        let bp = BivariatePolynomial::<p384::Scalar>::with_coefficients(vec![]);
        assert_eq!(bp.deg_x, 0);
        assert_eq!(bp.deg_y, 0);
        assert_eq!(bp.b, vec![scalars(&[0])]);

        let bp = BivariatePolynomial::<p384::Scalar>::with_coefficients(b.clone());
        assert_eq!(bp.deg_x, 1);
        assert_eq!(bp.deg_y, 2);
        assert_eq!(bp.b, b);

        let result = panic::catch_unwind(|| {
            _ = BivariatePolynomial::<p384::Scalar>::with_coefficients(vec![vec![]]);
        });
        assert!(result.is_err());

        let result = panic::catch_unwind(|| {
            _ = BivariatePolynomial::<p384::Scalar>::with_coefficients(vec![
                scalars(&[1, 2]),
                scalars(&[1]),
            ]);
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_random() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let bp = BivariatePolynomial::<p384::Scalar>::random(0, 0, &mut rng);
        assert_eq!(bp.deg_x, 0);
        assert_eq!(bp.deg_y, 0);
        assert_eq!(bp.b.len(), 1);
        assert_eq!(bp.b[0].len(), 1);
        assert_ne!(bp.b[0][0], scalar(0)); // Zero with negligible probability.

        let bp = BivariatePolynomial::<p384::Scalar>::random(2, 3, &mut rng);
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
        let mut bp = BivariatePolynomial::<p384::Scalar>::zero(2, 3);
        assert_eq!(bp.b[0][0], scalar(0));

        bp.set_coefficient(scalar(1), 0, 0);
        assert_eq!(bp.b[0][0], scalar(1));
    }

    #[test]
    fn test_to_zero_hole() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut bp = BivariatePolynomial::random(2, 3, &mut rng);

        bp.set_coefficient(scalar(1), 0, 0);
        assert_eq!(bp.b[0][0], scalar(1));

        bp.to_zero_hole();
        assert_eq!(bp.b[0][0], scalar(0));
    }

    #[test]
    fn test_serialization() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let bp = BivariatePolynomial::<p384::Scalar>::random(0, 0, &mut rng);
        let restored = BivariatePolynomial::<p384::Scalar>::from_bytes(bp.to_bytes())
            .expect("deserialization should succeed");
        assert!(bp == restored);

        let bp = BivariatePolynomial::<p384::Scalar>::random(2, 3, &mut rng);
        let restored = BivariatePolynomial::<p384::Scalar>::from_bytes(bp.to_bytes())
            .expect("deserialization should succeed");
        assert!(bp == restored);
    }

    #[test]
    fn test_coefficient_byte_size() {
        let size = BivariatePolynomial::<p384::Scalar>::coefficient_byte_size();
        assert_eq!(size, 48);
    }

    #[test]
    fn test_byte_size() {
        let size = BivariatePolynomial::<p384::Scalar>::byte_size(2, 3);
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
