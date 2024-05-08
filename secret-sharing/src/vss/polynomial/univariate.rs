use std::{
    cmp::{max, min},
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign},
};

use group::ff::PrimeField;
use rand_core::RngCore;

use crate::vss::{arith::powers, scalar::scalar_from_bytes};

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
#[derive(Clone, PartialEq, Eq)]
pub struct Polynomial<F> {
    pub(crate) a: Vec<F>,
}

impl<F> Polynomial<F>
where
    F: PrimeField,
{
    /// Creates a polynomial initialized to zero.
    pub fn zero(deg: u8) -> Self {
        let deg = deg as usize;

        let a = vec![F::ZERO; deg + 1];
        Self { a }
    }

    /// Creates a bivariate polynomial with random coefficients.
    pub fn random(deg: u8, rng: &mut impl RngCore) -> Self {
        let deg = deg as usize;

        let mut a = Vec::with_capacity(deg + 1);
        for _ in 0..a.capacity() {
            let ai = F::random(&mut *rng);
            a.push(ai);
        }

        Self::with_coefficients(a)
    }

    /// Creates a polynomial with the given coefficients.
    pub fn with_coefficients(a: Vec<F>) -> Self {
        if a.is_empty() {
            return Self::zero(0);
        }

        Self { a }
    }

    /// Sets the coefficient `a_i` that belongs to the term `x^i`.
    ///
    /// If the coefficient does not exist, this is a no-op.
    pub fn set_coefficient(&mut self, i: usize, ai: F) {
        if let Some(old_ai) = self.a.get_mut(i) {
            *old_ai = ai;
        }
    }

    /// Sets the coefficient `a_0` of the constant term to zero,
    /// effectively creating a zero-hole univariate polynomial.
    pub fn to_zero_hole(&mut self) {
        self.set_coefficient(0, F::ZERO);
    }

    /// Returns the highest of the degrees of the polynomial's monomials with
    /// non-zero coefficients.
    pub fn degree(&self) -> usize {
        let mut deg = self.a.len().saturating_sub(1);
        for ai in self.a.iter().rev() {
            if ai.is_zero().into() {
                deg = deg.saturating_sub(1);
            } else {
                break;
            }
        }

        deg
    }

    /// Returns the number of coefficients in the polynomial.
    pub fn size(&self) -> usize {
        self.a.len()
    }

    /// Returns the i-th coefficient of the polynomial.
    pub fn coefficient(&self, i: usize) -> Option<&F> {
        self.a.get(i)
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
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let size = Self::coefficient_byte_size();
        if bytes.is_empty() || bytes.len() % size != 0 {
            return None;
        }
        let deg = bytes.len() / size - 1;

        let mut bytes = bytes;
        let mut a = Vec::with_capacity(deg + 1);
        for _ in 0..=deg {
            let ai = match scalar_from_bytes(&bytes[..size]) {
                Some(ai) => ai,
                None => return None,
            };
            bytes = &bytes[size..];
            a.push(ai);
        }

        Some(Self::with_coefficients(a))
    }

    /// Returns the size of the byte representation of a coefficient.
    pub fn coefficient_byte_size() -> usize {
        F::NUM_BITS.saturating_add(7) as usize / 8
    }

    /// Returns the size of the byte representation of the polynomial.
    pub fn byte_size(deg: usize) -> usize {
        Self::coefficient_byte_size() * deg
    }

    /// Evaluates the polynomial.
    pub fn eval(&self, x: &F) -> F {
        let xpows = powers(x, self.a.len() - 1);
        let mut r = F::ZERO;
        for (i, xpow) in xpows.iter().enumerate() {
            r += self.a[i] * xpow
        }

        r
    }
}

impl<F> Default for Polynomial<F>
where
    F: PrimeField,
{
    fn default() -> Self {
        Self::zero(0)
    }
}

impl<F> Add for Polynomial<F>
where
    F: PrimeField,
{
    type Output = Self;

    fn add(self, other: Self) -> Self {
        &self + &other
    }
}

impl<F> Add for &Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    fn add(self, other: Self) -> Self::Output {
        let max_len = max(self.a.len(), other.a.len());
        let min_len = min(self.a.len(), other.a.len());
        let mut a = Vec::with_capacity(max_len);

        for i in 0..min_len {
            a.push(self.a[i] + other.a[i]);
        }

        a.extend(self.a[min_len..].iter());
        a.extend(other.a[min_len..].iter());

        Polynomial::with_coefficients(a)
    }
}

impl<F> AddAssign for Polynomial<F>
where
    F: PrimeField,
{
    fn add_assign(&mut self, other: Self) {
        *self += &other
    }
}

impl<F> AddAssign<&Self> for Polynomial<F>
where
    F: PrimeField,
{
    fn add_assign(&mut self, other: &Self) {
        let min_len = min(self.a.len(), other.a.len());

        for i in 0..min_len {
            self.a[i] += other.a[i];
        }

        self.a.extend(other.a[min_len..].iter());
    }
}

impl<F> Sub for Polynomial<F>
where
    F: PrimeField,
{
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        &self - &other
    }
}

impl<F> Sub for &Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    fn sub(self, other: Self) -> Self::Output {
        let max_len = max(self.a.len(), other.a.len());
        let min_len = min(self.a.len(), other.a.len());
        let mut a = Vec::with_capacity(max_len);

        for i in 0..min_len {
            a.push(self.a[i] - other.a[i]);
        }

        a.extend(self.a[min_len..].iter());
        a.extend(other.a[min_len..].iter().map(|ai| ai.neg()));

        Polynomial::with_coefficients(a)
    }
}

impl<F> SubAssign for Polynomial<F>
where
    F: PrimeField,
{
    fn sub_assign(&mut self, other: Self) {
        *self -= &other
    }
}

impl<F> SubAssign<&Self> for Polynomial<F>
where
    F: PrimeField,
{
    fn sub_assign(&mut self, other: &Self) {
        let min_len = min(self.a.len(), other.a.len());

        for i in 0..min_len {
            self.a[i] -= other.a[i];
        }

        self.a.extend(other.a[min_len..].iter().map(|ai| ai.neg()));
    }
}

impl<F> Mul for Polynomial<F>
where
    F: PrimeField,
{
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        &self * &other
    }
}

impl<F> Mul for &Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    fn mul(self, other: Self) -> Self::Output {
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
        Polynomial::with_coefficients(a)
    }
}

impl<F> MulAssign for Polynomial<F>
where
    F: PrimeField,
{
    fn mul_assign(&mut self, other: Self) {
        *self *= &other
    }
}

impl<F> MulAssign<&Self> for Polynomial<F>
where
    F: PrimeField,
{
    fn mul_assign(&mut self, other: &Self) {
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

impl<F> Mul<F> for Polynomial<F>
where
    F: PrimeField,
{
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn mul(self, scalar: F) -> Self {
        &self * &scalar
    }
}

impl<F> Mul<&F> for Polynomial<F>
where
    F: PrimeField,
{
    type Output = Self;

    fn mul(self, scalar: &F) -> Self {
        &self * scalar
    }
}

impl<F> Mul<F> for &Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    #[allow(clippy::op_ref)]
    fn mul(self, scalar: F) -> Self::Output {
        self * &scalar
    }
}

impl<F> Mul<&F> for &Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    fn mul(self, scalar: &F) -> Self::Output {
        let mut a = Vec::with_capacity(self.a.len());

        for i in 0..self.a.len() {
            a.push(self.a[i] * scalar);
        }

        Polynomial::with_coefficients(a)
    }
}

impl<F> MulAssign<F> for Polynomial<F>
where
    F: PrimeField,
{
    fn mul_assign(&mut self, scalar: F) {
        *self *= &scalar
    }
}

impl<F> MulAssign<&F> for Polynomial<F>
where
    F: PrimeField,
{
    fn mul_assign(&mut self, scalar: &F) {
        for i in 0..self.a.len() {
            self.a[i] *= scalar
        }
    }
}

impl<F> Sum for Polynomial<F>
where
    F: PrimeField,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut sum = Polynomial::zero(0);
        iter.for_each(|p| sum += p);
        sum
    }
}

impl<'a, F> Sum<&'a Self> for Polynomial<F>
where
    F: PrimeField,
{
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Polynomial<F> {
        let mut sum = Polynomial::zero(0);
        iter.for_each(|p| sum += p);
        sum
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    type PrimeField = p384::Scalar;
    type Polynomial = super::Polynomial<PrimeField>;

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
        let p = Polynomial::zero(0);
        assert_eq!(p.a, scalars(&[0]));

        let p = Polynomial::zero(2);
        assert_eq!(p.a, scalars(&[0, 0, 0]));
    }

    #[test]
    fn test_with_coefficients() {
        let p = Polynomial::with_coefficients(vec![]);
        assert_eq!(p.a, scalars(&[0]));

        let p = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        assert_eq!(p.a, scalars(&[1, 2, 3]));
    }

    #[test]
    fn test_set_coefficients() {
        let mut p = Polynomial::with_coefficients(scalars(&[1, 2, 3]));

        p.set_coefficient(3, scalar(4));
        assert_eq!(p.a, scalars(&[1, 2, 3]));

        p.set_coefficient(1, scalar(4));
        assert_eq!(p.a, scalars(&[1, 4, 3]));
    }

    #[test]
    fn test_zero_hole() {
        let mut p = Polynomial::with_coefficients(scalars(&[1, 2, 3]));

        p.to_zero_hole();
        assert_eq!(p.a, scalars(&[0, 2, 3]));
    }

    #[test]
    fn test_degree_and_size() {
        let p = Polynomial::with_coefficients(vec![]);
        assert_eq!(p.degree(), 0);
        assert_eq!(p.size(), 1);

        let p = Polynomial::with_coefficients(scalars(&[0]));
        assert_eq!(p.degree(), 0);
        assert_eq!(p.size(), 1);

        let p = Polynomial::with_coefficients(scalars(&[1]));
        assert_eq!(p.degree(), 0);
        assert_eq!(p.size(), 1);

        let p = Polynomial::with_coefficients(scalars(&[0, 0]));
        assert_eq!(p.degree(), 0);
        assert_eq!(p.size(), 2);

        let p = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        assert_eq!(p.degree(), 2);
        assert_eq!(p.size(), 3);

        let p = Polynomial::with_coefficients(scalars(&[1, 2, 3, 0, 0]));
        assert_eq!(p.degree(), 2);
        assert_eq!(p.size(), 5);

        let p = Polynomial::with_coefficients(scalars(&[0, 1, 2, 0, 3]));
        assert_eq!(p.degree(), 4);
        assert_eq!(p.size(), 5);
    }

    #[test]
    fn test_coefficient() {
        let p = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        assert_eq!(p.coefficient(0), Some(&scalar(1)));
        assert_eq!(p.coefficient(1), Some(&scalar(2)));
        assert_eq!(p.coefficient(2), Some(&scalar(3)));
        assert_eq!(p.coefficient(3), None);
    }

    #[test]
    fn test_trim() {
        let mut p = Polynomial::with_coefficients(scalars(&[0]));
        p.trim();
        assert_eq!(p.a, scalars(&[0]));

        let mut p = Polynomial::with_coefficients(scalars(&[0, 0]));
        p.trim();
        assert_eq!(p.a, scalars(&[0]));

        let mut p = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        p.trim();
        assert_eq!(p.a, scalars(&[1, 2, 3]));

        let mut p = Polynomial::with_coefficients(scalars(&[1, 2, 3, 0, 0]));
        p.trim();
        assert_eq!(p.a, scalars(&[1, 2, 3]));
    }

    #[test]
    fn test_serialization() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let bp = Polynomial::random(0, &mut rng);
        let restored =
            Polynomial::from_bytes(&bp.to_bytes()).expect("deserialization should succeed");
        assert!(bp == restored);

        let bp = Polynomial::random(3, &mut rng);
        let restored =
            Polynomial::from_bytes(&bp.to_bytes()).expect("deserialization should succeed");
        assert!(bp == restored);
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
        for h in vec![&f + &g, f + g] {
            assert_eq!(h.a, scalars(&[3, 6, 9]));
        }

        // Lower degree.
        let f = Polynomial::with_coefficients(scalars(&[1, 2]));
        let g = Polynomial::with_coefficients(scalars(&[2, 4, 6]));
        for h in vec![&f + &g, f + g] {
            assert_eq!(h.a, scalars(&[3, 6, 6]));
        }

        // Higher degree.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[2]));
        for h in vec![&f + &g, f + g] {
            assert_eq!(h.a, scalars(&[3, 2, 3]));
        }

        // Zero coefficients.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, -3, 4]));
        let g = Polynomial::with_coefficients(scalars(&[-1, 2, 3, -4]));
        for h in vec![&f + &g, f + g] {
            assert_eq!(h.a, scalars(&[0, 4, 0, 0]));
        }
    }

    #[test]
    pub fn test_add_assign() {
        let mut f1 = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let mut f2 = f1.clone();
        let g = Polynomial::with_coefficients(scalars(&[2, 4, 6]));
        f1 += &g;
        f2 += g;
        for f in vec![f1, f2] {
            assert_eq!(f.a, scalars(&[3, 6, 9]));
        }

        // Lower degree.
        let mut f1 = Polynomial::with_coefficients(scalars(&[1, 2]));
        let mut f2 = f1.clone();
        let g = Polynomial::with_coefficients(scalars(&[2, 4, 6]));
        f1 += &g;
        f2 += g;
        for f in vec![f1, f2] {
            assert_eq!(f.a, scalars(&[3, 6, 6]));
        }

        // Higher degree.
        let mut f1 = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let mut f2 = f1.clone();
        let g = Polynomial::with_coefficients(scalars(&[2]));
        f1 += &g;
        f2 += g;
        for f in vec![f1, f2] {
            assert_eq!(f.a, scalars(&[3, 2, 3]));
        }

        // Zero coefficients.
        let mut f1 = Polynomial::with_coefficients(scalars(&[1, 2, -3, 4]));
        let mut f2 = f1.clone();
        let g = Polynomial::with_coefficients(scalars(&[-1, 2, 3, -4]));
        f1 += &g;
        f2 += g;
        for f in vec![f1, f2] {
            assert_eq!(f.a, scalars(&[0, 4, 0, 0]));
        }
    }

    #[test]
    pub fn test_sub() {
        // Equal degree.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[2, 4, 6]));
        for h in vec![&f - &g, f - g] {
            assert_eq!(h.a, scalars(&[-1, -2, -3]));
        }

        // Lower degree.
        let f = Polynomial::with_coefficients(scalars(&[1, 2]));
        let g = Polynomial::with_coefficients(scalars(&[2, 4, 6]));
        for h in vec![&f - &g, f - g] {
            assert_eq!(h.a, scalars(&[-1, -2, -6]));
        }

        // Higher degree.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[2]));
        for h in vec![&f - &g, f - g] {
            assert_eq!(h.a, scalars(&[-1, 2, 3]));
        }

        // Zero coefficients.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3, 4]));
        let g = Polynomial::with_coefficients(scalars(&[1, -2, 3, 4]));
        for h in vec![&f - &g, f - g] {
            assert_eq!(h.a, scalars(&[0, 4, 0, 0]));
        }
    }

    #[test]
    pub fn test_sub_assign() {
        // Equal degree.
        let mut f1 = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let mut f2 = f1.clone();
        let g = Polynomial::with_coefficients(scalars(&[2, 4, 6]));
        f1 -= &g;
        f2 -= g;
        for f in vec![f1, f2] {
            assert_eq!(f.a, scalars(&[-1, -2, -3]));
        }

        // Lower degree.
        let mut f1 = Polynomial::with_coefficients(scalars(&[1, 2]));
        let mut f2 = f1.clone();
        let g = Polynomial::with_coefficients(scalars(&[2, 4, 6]));
        f1 -= &g;
        f2 -= g;
        for f in vec![f1, f2] {
            assert_eq!(f.a, scalars(&[-1, -2, -6]));
        }

        // Higher degree.
        let mut f1 = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let mut f2 = f1.clone();
        let g = Polynomial::with_coefficients(scalars(&[2]));
        f1 -= &g;
        f2 -= g;
        for f in vec![f1, f2] {
            assert_eq!(f.a, scalars(&[-1, 2, 3]));
        }

        // Zero coefficients.
        let mut f1 = Polynomial::with_coefficients(scalars(&[1, 2, 3, 4]));
        let mut f2 = f1.clone();
        let g = Polynomial::with_coefficients(scalars(&[1, -2, 3, 4]));
        f1 -= &g;
        f2 -= g;
        for f in vec![f1, f2] {
            assert_eq!(f.a, scalars(&[0, 4, 0, 0]));
        }
    }

    #[test]
    pub fn test_mul() {
        // Non-zero.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[2, 4]));
        for h in vec![&f * &g, f * g] {
            assert_eq!(h.a, scalars(&[2, 8, 14, 12]));
        }

        // Zero.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[0]));
        for h in vec![&f * &g, f * g] {
            assert_eq!(h.a, scalars(&[0, 0, 0]));
        }
    }

    #[test]
    pub fn test_mul_assign() {
        // Non-zero.
        let mut f1 = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let mut f2 = f1.clone();
        let g = Polynomial::with_coefficients(scalars(&[2, 4]));
        f1 *= &g;
        f2 *= g;
        for f in vec![f1, f2] {
            assert_eq!(f.a, scalars(&[2, 8, 14, 12]));
        }

        // Zero.
        let mut f1 = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let mut f2 = f1.clone();
        let g = Polynomial::with_coefficients(scalars(&[0]));
        f1 *= &g;
        f2 *= g;
        for f in vec![f1, f2] {
            assert_eq!(f.a, scalars(&[0, 0, 0]));
        }
    }

    #[test]
    pub fn test_scalar_mul() {
        // Non-zero.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let s = scalars(&[2])[0];
        for g in vec![&f * &s, f.clone() * s, &f * s, f * &s] {
            assert_eq!(g.a, scalars(&[2, 4, 6]));
        }

        // Zero.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let s = scalars(&[0])[0];
        for g in vec![&f * &s, f.clone() * s, &f * s, f * &s] {
            assert_eq!(g.a, scalars(&[0, 0, 0]));
        }
    }

    #[test]
    pub fn test_scalar_mul_assign() {
        // Non-zero.
        let mut f1 = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let mut f2 = f1.clone();
        let s = scalars(&[2])[0];
        f1 *= &s;
        f2 *= s;
        for f in vec![f1, f2] {
            assert_eq!(f.a, scalars(&[2, 4, 6]));
        }

        // Zero.
        let mut f1 = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let mut f2 = f1.clone();
        let s = scalars(&[0])[0];
        f1 *= &s;
        f2 *= s;
        for f in vec![f1, f2] {
            assert_eq!(f.a, scalars(&[0, 0, 0]));
        }
    }

    #[test]
    pub fn test_sum() {
        // One.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let s1 = vec![&f].into_iter().sum::<Polynomial>();
        let s2 = vec![f].into_iter().sum::<Polynomial>();
        for s in vec![s1, s2] {
            assert_eq!(s.a, scalars(&[1, 2, 3]));
        }

        // Many.
        let f = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        let g = Polynomial::with_coefficients(scalars(&[2, 4]));
        let h = Polynomial::with_coefficients(scalars(&[3]));
        let s1 = vec![&f, &g, &h].into_iter().sum::<Polynomial>();
        let s2 = vec![f, g, h].into_iter().sum::<Polynomial>();
        for s in vec![s1, s2] {
            assert_eq!(s.a, scalars(&[6, 6, 3]));
        }
    }
}
