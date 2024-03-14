use std::{
    cmp::{max, min},
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign},
};

use group::ff::PrimeField;
use rand_core::RngCore;

use crate::vss::arith::powers;

/// Univariate polynomial over a non-binary prime field.
///
/// ```text
/// A(x) = \sum_{i=0}^{deg_x} a_i x^i
/// ```
///
/// The constant zero polynomial is represented by a vector with one zero
/// element, rather than by an empty vector.
///
/// Trailing zeros are never trimmed to ensure that all polynomials of the same
/// degree are consistently represented by vectors of the same size, resulting
/// in encodings of equal length. If you wish to remove them, consider using
/// the `trim` method after each operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial<Fp> {
    a: Vec<Fp>,
}

impl<Fp> Polynomial<Fp>
where
    Fp: PrimeField,
{
    /// Creates a polynomial initialized to zero.
    pub fn zero(deg: u8) -> Self {
        let deg = deg as usize;

        let a = vec![Fp::ZERO; deg + 1];
        Self { a }
    }

    /// Creates a bivariate polynomial with random coefficients.
    pub fn random(deg: u8, rng: &mut impl RngCore) -> Self {
        let deg = deg as usize;

        let mut a = Vec::with_capacity(deg + 1);
        for _ in 0..a.capacity() {
            let ai = Fp::random(&mut *rng);
            a.push(ai);
        }

        Self::with_coefficients(a)
    }

    /// Creates a polynomial with the given coefficients.
    pub fn with_coefficients(a: Vec<Fp>) -> Self {
        if a.is_empty() {
            return Self::zero(0);
        }

        Self { a }
    }

    /// Returns the highest of the degrees of the polynomial's monomials with
    /// non-zero coefficients.
    pub fn degree(&self) -> usize {
        let mut deg = self.a.len().saturating_sub(1);
        for ai in self.a.iter().rev() {
            if ai.is_zero().into() {
                deg = deg.saturating_sub(1);
            }
        }

        deg
    }

    /// Returns the number of coefficients in the polynomial.
    pub fn size(&self) -> usize {
        self.a.len()
    }

    /// Removes trailing zeros.
    pub fn trim(&mut self) {
        while self.a.len() > 1 && self.a[self.a.len() - 1].is_zero().into() {
            _ = self.a.pop();
        }
    }

    /// Returns the byte representation of the polynomial.
    pub fn to_bytes(&self) -> Vec<u8> {
        let cap = Self::byte_size(self.a.len());
        let mut bytes = Vec::with_capacity(cap);
        for ai in &self.a {
            bytes.extend_from_slice(ai.to_repr().as_ref());
        }

        bytes
    }

    /// Attempts to create a polynomial from its byte representation.
    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        let size = Self::coefficient_byte_size();
        if bytes.is_empty() || bytes.len() % size != 0 {
            return None;
        }
        let deg = bytes.len() / size - 1;

        let mut bytes = &bytes[..];
        let mut a = Vec::with_capacity(deg + 1);
        for _ in 0..=deg {
            let mut repr: Fp::Repr = Default::default();
            let slice = &mut repr.as_mut()[..];
            let (ai, rest) = bytes.split_at(slice.len());
            slice.copy_from_slice(ai);
            bytes = rest;

            let ai = match Fp::from_repr(repr).into() {
                None => return None,
                Some(ai) => ai,
            };

            a.push(ai);
        }

        Some(Self::with_coefficients(a))
    }

    /// Returns the size of the byte representation of a coefficient.
    pub fn coefficient_byte_size() -> usize {
        Fp::NUM_BITS.saturating_add(7) as usize / 8
    }

    /// Returns the size of the byte representation of the polynomial.
    pub fn byte_size(deg: usize) -> usize {
        Self::coefficient_byte_size() * deg
    }

    /// Evaluates the polynomial.
    pub fn eval(&self, x: &Fp) -> Fp {
        let xpows = powers(x, self.a.len() - 1);
        let mut r = Fp::ZERO;
        for (i, xpow) in xpows.iter().enumerate() {
            r += self.a[i] * xpow
        }

        r
    }
}

impl<Fp> Default for Polynomial<Fp>
where
    Fp: PrimeField,
{
    fn default() -> Self {
        Self::zero(0)
    }
}

impl<Fp> Add for Polynomial<Fp>
where
    Fp: PrimeField,
{
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let max_len = max(self.a.len(), other.a.len());
        let min_len = min(self.a.len(), other.a.len());
        let mut a = Vec::with_capacity(max_len);

        for i in 0..min_len {
            a.push(self.a[i] + other.a[i]);
        }

        a.extend(self.a[min_len..].iter());
        a.extend(other.a[min_len..].iter());

        Self::with_coefficients(a)
    }
}

impl<Fp> AddAssign for Polynomial<Fp>
where
    Fp: PrimeField,
{
    fn add_assign(&mut self, other: Self) {
        let min_len = min(self.a.len(), other.a.len());

        for i in 0..min_len {
            self.a[i] += other.a[i];
        }

        self.a.extend(other.a[min_len..].iter());
    }
}

impl<Fp> Sub for Polynomial<Fp>
where
    Fp: PrimeField,
{
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let max_len = max(self.a.len(), other.a.len());
        let min_len = min(self.a.len(), other.a.len());
        let mut a = Vec::with_capacity(max_len);

        for i in 0..min_len {
            a.push(self.a[i] - other.a[i]);
        }

        a.extend(self.a[min_len..].iter());
        a.extend(other.a[min_len..].iter().map(|ai| ai.neg()));

        Self::with_coefficients(a)
    }
}

impl<Fp> SubAssign for Polynomial<Fp>
where
    Fp: PrimeField,
{
    fn sub_assign(&mut self, other: Self) {
        let min_len = min(self.a.len(), other.a.len());

        for i in 0..min_len {
            self.a[i] -= other.a[i];
        }

        self.a.extend(other.a[min_len..].iter().map(|ai| ai.neg()));
    }
}

impl<Fp> Mul for Polynomial<Fp>
where
    Fp: PrimeField,
{
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let mut a = Vec::with_capacity(self.a.len() + other.a.len() - 1);
        for i in 0..self.a.len() {
            for j in 0..other.a.len() {
                let aij = self.a[i] * other.a[j];
                if i + j < a.len() {
                    a[i + j] += aij;
                } else {
                    a.push(aij);
                }
            }
        }
        Self::with_coefficients(a)
    }
}

impl<Fp> MulAssign for Polynomial<Fp>
where
    Fp: PrimeField,
{
    fn mul_assign(&mut self, other: Self) {
        let mut a = Vec::with_capacity(self.a.len() + other.a.len() - 2);
        for i in 0..self.a.len() {
            for j in 0..other.a.len() {
                let aij = self.a[i] * other.a[j];
                if i + j < a.len() {
                    a[i + j] += aij;
                } else {
                    a.push(aij);
                }
            }
        }
        self.a = a;
    }
}

impl<Fp> Mul<Fp> for Polynomial<Fp>
where
    Fp: PrimeField,
{
    type Output = Self;

    fn mul(self, scalar: Fp) -> Self {
        let mut a = Vec::with_capacity(self.a.len());

        for i in 0..self.a.len() {
            a.push(self.a[i] * scalar);
        }

        Self::with_coefficients(a)
    }
}

impl<Fp> MulAssign<Fp> for Polynomial<Fp>
where
    Fp: PrimeField,
{
    fn mul_assign(&mut self, scalar: Fp) {
        for i in 0..self.a.len() {
            self.a[i] *= scalar
        }
    }
}

impl<Fp> Sum for Polynomial<Fp>
where
    Fp: PrimeField,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut sum = Self::zero(0);
        iter.for_each(|p| sum += p);
        sum
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::Polynomial;

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
        let p = Polynomial::<p384::Scalar>::zero(0);
        assert_eq!(p.a, scalars(&[0]));

        let p = Polynomial::<p384::Scalar>::zero(2);
        assert_eq!(p.a, scalars(&[0, 0, 0]));
    }

    #[test]
    fn test_with_coefficients() {
        let p = Polynomial::<p384::Scalar>::with_coefficients(vec![]);
        assert_eq!(p.a, scalars(&[0]));

        let p = Polynomial::<p384::Scalar>::with_coefficients(scalars(&[1, 2, 3]));
        assert_eq!(p.a, scalars(&[1, 2, 3]));
    }

    #[test]
    fn test_degree_and_size() {
        let p = Polynomial::<p384::Scalar>::with_coefficients(vec![]);
        assert_eq!(p.degree(), 0);
        assert_eq!(p.size(), 1);

        let p = Polynomial::<p384::Scalar>::with_coefficients(scalars(&[0]));
        assert_eq!(p.degree(), 0);
        assert_eq!(p.size(), 1);

        let p = Polynomial::<p384::Scalar>::with_coefficients(scalars(&[1]));
        assert_eq!(p.degree(), 0);
        assert_eq!(p.size(), 1);

        let p = Polynomial::<p384::Scalar>::with_coefficients(scalars(&[0, 0]));
        assert_eq!(p.degree(), 0);
        assert_eq!(p.size(), 2);

        let p = Polynomial::<p384::Scalar>::with_coefficients(scalars(&[1, 2, 3]));
        assert_eq!(p.degree(), 2);
        assert_eq!(p.size(), 3);

        let p = Polynomial::<p384::Scalar>::with_coefficients(scalars(&[1, 2, 3, 0, 0]));
        assert_eq!(p.degree(), 2);
        assert_eq!(p.size(), 5);
    }

    #[test]
    fn test_trim() {
        let mut p = Polynomial::<p384::Scalar>::with_coefficients(scalars(&[0]));
        p.trim();
        assert_eq!(p.a, scalars(&[0]));

        let mut p = Polynomial::<p384::Scalar>::with_coefficients(scalars(&[0, 0]));
        p.trim();
        assert_eq!(p.a, scalars(&[0]));

        let mut p = Polynomial::<p384::Scalar>::with_coefficients(scalars(&[1, 2, 3]));
        p.trim();
        assert_eq!(p.a, scalars(&[1, 2, 3]));

        let mut p = Polynomial::<p384::Scalar>::with_coefficients(scalars(&[1, 2, 3, 0, 0]));
        p.trim();
        assert_eq!(p.a, scalars(&[1, 2, 3]));
    }

    #[test]
    fn test_serialization() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let bp = Polynomial::<p384::Scalar>::random(0, &mut rng);
        let restored = Polynomial::<p384::Scalar>::from_bytes(bp.to_bytes())
            .expect("deserialization should succeed");
        assert_eq!(bp, restored);

        let bp = Polynomial::<p384::Scalar>::random(3, &mut rng);
        let restored = Polynomial::<p384::Scalar>::from_bytes(bp.to_bytes())
            .expect("deserialization should succeed");
        assert_eq!(bp, restored);
    }

    #[test]
    pub fn test_eval() {
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));

        let r = f.eval(&scalar(0));
        assert_eq!(r, scalar(1 + 2 * 0 + 3 * 0 * 0));

        let r = f.eval(&scalar(1));
        assert_eq!(r, scalar(1 + 2 * 1 + 3 * 1 * 1));

        let r = f.eval(&scalar(2));
        assert_eq!(r, scalar(1 + 2 * 2 + 3 * 2 * 2));
    }

    #[test]
    pub fn test_add() {
        // Equal degree.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[2, 4, 6]));
        let h = f + g;
        assert_eq!(h.a, scalars(&[3, 6, 9]));

        // Lower degree.
        let f = Polynomial::with_coefficients(scalars(&[1, 2]));
        let g = Polynomial::with_coefficients(scalars(&[2, 4, 6]));
        let h = f + g;
        assert_eq!(h.a, scalars(&[3, 6, 6]));

        // Higher degree.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[2]));
        let h = f + g;
        assert_eq!(h.a, scalars(&[3, 2, 3]));

        // Zero coefficients.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, -3, 4]));
        let g = Polynomial::with_coefficients(scalars(&[-1, 2, 3, -4]));
        let h = f + g;
        assert_eq!(h.a, scalars(&[0, 4, 0, 0]));
    }

    #[test]
    pub fn test_add_assign() {
        let mut f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[2, 4, 6]));
        f += g;
        assert_eq!(f.a, scalars(&[3, 6, 9]));

        // Lower degree.
        let mut f = Polynomial::with_coefficients(scalars(&[1, 2]));
        let g = Polynomial::with_coefficients(scalars(&[2, 4, 6]));
        f += g;
        assert_eq!(f.a, scalars(&[3, 6, 6]));

        // Higher degree.
        let mut f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[2]));
        f += g;
        assert_eq!(f.a, scalars(&[3, 2, 3]));

        // Zero coefficients.
        let mut f = Polynomial::with_coefficients(scalars(&[1, 2, -3, 4]));
        let g = Polynomial::with_coefficients(scalars(&[-1, 2, 3, -4]));
        f += g;
        assert_eq!(f.a, scalars(&[0, 4, 0, 0]));
    }

    #[test]
    pub fn test_sub() {
        // Equal degree.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[2, 4, 6]));
        let h = f - g;
        assert_eq!(h.a, scalars(&[-1, -2, -3]));

        // Lower degree.
        let f = Polynomial::with_coefficients(scalars(&[1, 2]));
        let g = Polynomial::with_coefficients(scalars(&[2, 4, 6]));
        let h = f - g;
        assert_eq!(h.a, scalars(&[-1, -2, -6]));

        // Higher degree.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[2]));
        let h = f - g;
        assert_eq!(h.a, scalars(&[-1, 2, 3]));

        // Zero coefficients.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3, 4]));
        let g = Polynomial::with_coefficients(scalars(&[1, -2, 3, 4]));
        let h = f - g;
        assert_eq!(h.a, scalars(&[0, 4, 0, 0]));
    }

    #[test]
    pub fn test_sub_assign() {
        // Equal degree.
        let mut f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[2, 4, 6]));
        f -= g;
        assert_eq!(f.a, scalars(&[-1, -2, -3]));

        // Lower degree.
        let mut f = Polynomial::with_coefficients(scalars(&[1, 2]));
        let g = Polynomial::with_coefficients(scalars(&[2, 4, 6]));
        f -= g;
        assert_eq!(f.a, scalars(&[-1, -2, -6]));

        // Higher degree.
        let mut f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[2]));
        f -= g;
        assert_eq!(f.a, scalars(&[-1, 2, 3]));

        // Zero coefficients.
        let mut f = Polynomial::with_coefficients(scalars(&[1, 2, 3, 4]));
        let g = Polynomial::with_coefficients(scalars(&[1, -2, 3, 4]));
        f -= g;
        assert_eq!(f.a, scalars(&[0, 4, 0, 0]));
    }

    #[test]
    pub fn test_mul() {
        // Non-zero.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[2, 4]));
        let h = f * g;
        assert_eq!(h.a, scalars(&[2, 8, 14, 12]));

        // Zero.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[0]));
        let h = f * g;
        assert_eq!(h.a, scalars(&[0, 0, 0]));
    }

    #[test]
    pub fn test_mul_assign() {
        // Non-zero.
        let mut f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[2, 4]));
        f *= g;
        assert_eq!(f.a, scalars(&[2, 8, 14, 12]));

        // Zero.
        let mut f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[0]));
        f *= g;
        assert_eq!(f.a, scalars(&[0, 0, 0]));
    }

    #[test]
    pub fn test_scalar_mul() {
        // Non-zero.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let s = scalars(&[2])[0];
        let g = f * s;
        assert_eq!(g.a, scalars(&[2, 4, 6]));

        // Zero.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let s = scalars(&[0])[0];
        let g = f * s;
        assert_eq!(g.a, scalars(&[0, 0, 0]));
    }

    #[test]
    pub fn test_scalar_mul_assign() {
        // Non-zero.
        let mut f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let s = scalars(&[2])[0];
        f *= s;
        assert_eq!(f.a, scalars(&[2, 4, 6]));

        // Zero.
        let mut f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let s = scalars(&[0])[0];
        f *= s;
        assert_eq!(f.a, scalars(&[0, 0, 0]));
    }

    #[test]
    pub fn test_sum() {
        // One.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let s = vec![f].into_iter().sum::<Polynomial<_>>();
        assert_eq!(s.a, scalars(&[1, 2, 3]));

        // Many.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[2, 4]));
        let h = Polynomial::with_coefficients(scalars(&[3]));
        let s = vec![f, g, h].into_iter().sum::<Polynomial<_>>();
        assert_eq!(s.a, scalars(&[6, 6, 3]));
    }
}
