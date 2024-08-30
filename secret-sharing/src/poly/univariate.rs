use std::{
    cmp::{max, min},
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign},
};

use group::ff::PrimeField;
use rand_core::RngCore;
use subtle::{Choice, CtOption};

use crate::poly::powers;

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
/// in encodings of equal length.
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
    ///
    /// This method is not constant time as some prime field implementations
    /// may generate uniformly random elements using rejection sampling.
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
    pub fn set_coefficient(&mut self, i: usize, ai: F) -> bool {
        if let Some(old_ai) = self.a.get_mut(i) {
            *old_ai = ai;
            return true;
        }
        false
    }

    /// Sets the coefficient `a_0` of the constant term to zero,
    /// effectively creating a zero-hole univariate polynomial.
    pub fn to_zero_hole(&mut self) {
        let updated = self.set_coefficient(0, F::ZERO);
        debug_assert!(updated)
    }

    /// Returns true iff the coefficient `a_0` of the constant term is zero.
    pub fn is_zero_hole(&self) -> bool {
        self.a[0].is_zero().into()
    }

    /// Returns the number of coefficients in the polynomial.
    pub fn size(&self) -> usize {
        self.a.len()
    }

    /// Returns the i-th coefficient of the polynomial.
    pub fn coefficient(&self, i: usize) -> Option<&F> {
        self.a.get(i)
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
    ///
    /// This method is not constant time if the length of the slice is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        // Short-circuit on the length of the slice, not its contents.
        let coefficient_size = Self::coefficient_byte_size();

        if bytes.is_empty() || bytes.len() % coefficient_size != 0 {
            return None;
        }

        // Don't short-circuit this loop to avoid revealing which coefficient
        // failed to decode.
        let num_coefficients = bytes.len() / coefficient_size;
        let mut a = Vec::with_capacity(num_coefficients);
        let mut failed = Choice::from(0);

        for chunk in bytes.chunks(coefficient_size) {
            let mut repr: F::Repr = Default::default();
            repr.as_mut().copy_from_slice(chunk);

            let maybe_ai = F::from_repr(repr);
            failed |= maybe_ai.is_none();

            let ai = maybe_ai.unwrap_or(Default::default());
            a.push(ai);
        }

        let p = Self::with_coefficients(a);
        let res = CtOption::new(p, !failed);

        res.into()
    }

    /// Returns the size of the byte representation of a coefficient.
    pub const fn coefficient_byte_size() -> usize {
        F::NUM_BITS.saturating_add(7) as usize / 8
    }

    /// Returns the size of the byte representation of the polynomial.
    pub const fn byte_size(deg: usize) -> usize {
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

//
// Implementations of the `core::ops` traits.
//

impl<F> Add for Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    fn add(self, rhs: Polynomial<F>) -> Polynomial<F> {
        &self + &rhs
    }
}

impl<F> Add<&Polynomial<F>> for Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    fn add(self, rhs: &Polynomial<F>) -> Polynomial<F> {
        &self + rhs
    }
}

impl<F> Add<Polynomial<F>> for &Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    fn add(self, rhs: Polynomial<F>) -> Polynomial<F> {
        self + &rhs
    }
}

impl<F> Add for &Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    fn add(self, rhs: &Polynomial<F>) -> Polynomial<F> {
        let max_len = max(self.a.len(), rhs.a.len());
        let min_len = min(self.a.len(), rhs.a.len());
        let mut a = Vec::with_capacity(max_len);

        for i in 0..min_len {
            a.push(self.a[i] + rhs.a[i]);
        }

        a.extend(self.a[min_len..].iter());
        a.extend(rhs.a[min_len..].iter());

        Polynomial::with_coefficients(a)
    }
}

impl<F> AddAssign for Polynomial<F>
where
    F: PrimeField,
{
    fn add_assign(&mut self, rhs: Polynomial<F>) {
        *self += &rhs
    }
}

impl<F> AddAssign<&Polynomial<F>> for Polynomial<F>
where
    F: PrimeField,
{
    fn add_assign(&mut self, rhs: &Polynomial<F>) {
        let min_len = min(self.a.len(), rhs.a.len());

        for i in 0..min_len {
            self.a[i] += rhs.a[i];
        }

        self.a.extend(rhs.a[min_len..].iter());
    }
}

impl<F> Sub for Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    fn sub(self, rhs: Polynomial<F>) -> Polynomial<F> {
        &self - &rhs
    }
}

impl<F> Sub<&Polynomial<F>> for Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    fn sub(self, rhs: &Polynomial<F>) -> Polynomial<F> {
        &self - rhs
    }
}

impl<F> Sub<Polynomial<F>> for &Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    fn sub(self, rhs: Polynomial<F>) -> Polynomial<F> {
        self - &rhs
    }
}

impl<F> Sub for &Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    fn sub(self, rhs: &Polynomial<F>) -> Polynomial<F> {
        let max_len = max(self.a.len(), rhs.a.len());
        let min_len = min(self.a.len(), rhs.a.len());
        let mut a = Vec::with_capacity(max_len);

        for i in 0..min_len {
            a.push(self.a[i] - rhs.a[i]);
        }

        a.extend(self.a[min_len..].iter());
        a.extend(rhs.a[min_len..].iter().map(|ai| ai.neg()));

        Polynomial::with_coefficients(a)
    }
}

impl<F> SubAssign for Polynomial<F>
where
    F: PrimeField,
{
    fn sub_assign(&mut self, rhs: Polynomial<F>) {
        *self -= &rhs
    }
}

impl<F> SubAssign<&Polynomial<F>> for Polynomial<F>
where
    F: PrimeField,
{
    fn sub_assign(&mut self, rhs: &Polynomial<F>) {
        let min_len = min(self.a.len(), rhs.a.len());

        for i in 0..min_len {
            self.a[i] -= rhs.a[i];
        }

        self.a.extend(rhs.a[min_len..].iter().map(|ai| ai.neg()));
    }
}

impl<F> Mul for Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    fn mul(self, rhs: Polynomial<F>) -> Polynomial<F> {
        &self * &rhs
    }
}

impl<F> Mul<&Polynomial<F>> for Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    fn mul(self, rhs: &Polynomial<F>) -> Polynomial<F> {
        &self * rhs
    }
}

impl<F> Mul<Polynomial<F>> for &Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    fn mul(self, rhs: Polynomial<F>) -> Polynomial<F> {
        self * &rhs
    }
}

impl<F> Mul for &Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    fn mul(self, rhs: &Polynomial<F>) -> Polynomial<F> {
        let mut a = Vec::with_capacity(self.a.len() + rhs.a.len() - 1);
        for i in 0..self.a.len() {
            for j in 0..rhs.a.len() {
                let aij = self.a[i] * rhs.a[j];
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
    fn mul_assign(&mut self, rhs: Polynomial<F>) {
        *self *= &rhs
    }
}

impl<F> MulAssign<&Polynomial<F>> for Polynomial<F>
where
    F: PrimeField,
{
    fn mul_assign(&mut self, rhs: &Polynomial<F>) {
        let mut a = Vec::with_capacity(self.a.len() + rhs.a.len() - 2);
        for i in 0..self.a.len() {
            for j in 0..rhs.a.len() {
                let aij = self.a[i] * rhs.a[j];
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
    type Output = Polynomial<F>;

    #[allow(clippy::op_ref)]
    fn mul(self, scalar: F) -> Polynomial<F> {
        &self * &scalar
    }
}

impl<F> Mul<&F> for Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    fn mul(self, scalar: &F) -> Polynomial<F> {
        &self * scalar
    }
}

impl<F> Mul<F> for &Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    #[allow(clippy::op_ref)]
    fn mul(self, scalar: F) -> Polynomial<F> {
        self * &scalar
    }
}

impl<F> Mul<&F> for &Polynomial<F>
where
    F: PrimeField,
{
    type Output = Polynomial<F>;

    fn mul(self, scalar: &F) -> Polynomial<F> {
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
    fn sum<I: Iterator<Item = Polynomial<F>>>(iter: I) -> Polynomial<F> {
        let mut sum = Polynomial::zero(0);
        iter.for_each(|p| sum += p);
        sum
    }
}

impl<'a, F> Sum<&'a Polynomial<F>> for Polynomial<F>
where
    F: PrimeField,
{
    fn sum<I: Iterator<Item = &'a Polynomial<F>>>(iter: I) -> Polynomial<F> {
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

        assert!(!p.set_coefficient(3, scalar(4)));
        assert_eq!(p.a, scalars(&[1, 2, 3]));

        assert!(p.set_coefficient(1, scalar(4)));
        assert_eq!(p.a, scalars(&[1, 4, 3]));
    }

    #[test]
    fn test_zero_hole() {
        let mut p = Polynomial::with_coefficients(scalars(&[1, 2, 3]));

        p.to_zero_hole();
        assert_eq!(p.a, scalars(&[0, 2, 3]));
    }

    #[test]
    fn test_is_zero_hole() {
        // The constant term is 1.
        let mut p = Polynomial::with_coefficients(scalars(&[1, 2, 3]));
        assert!(!p.is_zero_hole());

        // The constant term is 0.
        p.to_zero_hole();
        assert!(p.is_zero_hole());
    }

    #[test]
    fn test_size() {
        let test_cases = vec![
            (1, vec![]),
            (1, vec![0]),
            (1, vec![1]),
            (2, vec![0, 0]),
            (3, vec![1, 2, 3]),
            (5, vec![1, 2, 3, 0, 0]),
            (5, vec![0, 1, 2, 0, 3]),
        ];

        for (size, coefficients) in test_cases {
            let p = Polynomial::with_coefficients(scalars(&coefficients));
            assert_eq!(p.size(), size);
        }
    }

    #[test]
    fn test_coefficient() {
        let a = scalars(&[1, 2, 3]);
        let p = Polynomial::with_coefficients(a.clone());

        // Test coefficients within bounds.
        for i in 0..a.len() {
            assert_eq!(p.coefficient(i), Some(&a[i]));
        }

        // Test coefficients out of bounds.
        assert_eq!(p.coefficient(3), None);
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
        let test_cases = vec![
            // Equal degree.
            (vec![1, 2, 3], vec![2, 4, 6], vec![3, 6, 9]),
            // Lower degree.
            (vec![1, 2], vec![2, 4, 6], vec![3, 6, 6]),
            // Higher degree.
            (vec![1, 2, 3], vec![2], vec![3, 2, 3]),
            // Zero coefficients.
            (vec![1, 2, -3, 4], vec![-1, 2, 3, -4], vec![0, 4, 0, 0]),
        ];

        for (coefficients_f, coefficients_g, coefficients_h) in test_cases {
            let f = Polynomial::with_coefficients(scalars(&coefficients_f));
            let g = Polynomial::with_coefficients(scalars(&coefficients_g));
            let h = Polynomial::with_coefficients(scalars(&coefficients_h));

            // Test add.
            let v = f.clone() + g.clone();
            assert_eq!(v.a, h.a);

            let v = f.clone() + &g.clone();
            assert_eq!(v.a, h.a);

            let v = &f.clone() + g.clone();
            assert_eq!(v.a, h.a);

            let v = &f.clone() + &g.clone();
            assert_eq!(v.a, h.a);

            // Test add assign.
            let mut v = f.clone();
            v += g.clone();
            assert_eq!(v.a, h.a);

            let mut v = f.clone();
            v += &g.clone();
            assert_eq!(v.a, h.a);
        }
    }

    #[test]
    pub fn test_sub() {
        let test_cases = vec![
            // Equal degree.
            (vec![1, 2, 3], vec![2, 4, 6], vec![-1, -2, -3]),
            // Lower degree.
            (vec![1, 2], vec![2, 4, 6], vec![-1, -2, -6]),
            // Higher degree.
            (vec![1, 2, 3], vec![2], vec![-1, 2, 3]),
            // Zero coefficients.
            (vec![1, 2, 3, 4], vec![1, -2, 3, 4], vec![0, 4, 0, 0]),
        ];

        for (coefficients_f, coefficients_g, coefficients_h) in test_cases {
            let f = Polynomial::with_coefficients(scalars(&coefficients_f));
            let g = Polynomial::with_coefficients(scalars(&coefficients_g));
            let h = Polynomial::with_coefficients(scalars(&coefficients_h));

            // Test sub.
            let v = f.clone() - g.clone();
            assert_eq!(v.a, h.a);

            let v = f.clone() - &g.clone();
            assert_eq!(v.a, h.a);

            let v = &f.clone() - g.clone();
            assert_eq!(v.a, h.a);

            let v = &f.clone() - &g.clone();
            assert_eq!(v.a, h.a);

            // Test sub assign.
            let mut v = f.clone();
            v -= g.clone();
            assert_eq!(v.a, h.a);

            let mut v = f.clone();
            v -= &g.clone();
            assert_eq!(v.a, h.a);
        }
    }

    #[test]
    pub fn test_mul() {
        let test_cases = vec![
            // Non-zero.
            (vec![1, 2, 3], vec![2, 4], vec![2, 8, 14, 12]),
            // Zero.
            (vec![1, 2, 3], vec![0], vec![0, 0, 0]),
        ];

        for (coefficients_f, coefficients_g, coefficients_h) in test_cases {
            let f = Polynomial::with_coefficients(scalars(&coefficients_f));
            let g = Polynomial::with_coefficients(scalars(&coefficients_g));
            let h = Polynomial::with_coefficients(scalars(&coefficients_h));

            // Test mul.
            let v = f.clone() * g.clone();
            assert_eq!(v.a, h.a);

            let v = f.clone() * &g.clone();
            assert_eq!(v.a, h.a);

            let v = &f.clone() * g.clone();
            assert_eq!(v.a, h.a);

            let v = &f.clone() * &g.clone();
            assert_eq!(v.a, h.a);

            // Test mul assign.
            let mut v = f.clone();
            v *= g.clone();
            assert_eq!(v.a, h.a);

            let mut v = f.clone();
            v *= &g.clone();
            assert_eq!(v.a, h.a);
        }
    }

    #[test]
    pub fn test_scalar_mul() {
        let test_cases = vec![
            // Non-zero.
            (vec![1, 2, 3], 2, vec![2, 4, 6]),
            // Zero.
            (vec![1, 2, 3], 0, vec![0, 0, 0]),
        ];

        for (coefficients_f, scalar_s, coefficients_h) in test_cases {
            let f = Polynomial::with_coefficients(scalars(&coefficients_f));
            let s = scalar(scalar_s);
            let h = Polynomial::with_coefficients(scalars(&coefficients_h));

            // Test scalar mul.
            let v = f.clone() * s.clone();
            assert_eq!(v.a, h.a);

            let v = f.clone() * &s.clone();
            assert_eq!(v.a, h.a);

            let v = &f.clone() * s.clone();
            assert_eq!(v.a, h.a);

            let v = &f.clone() * &s.clone();
            assert_eq!(v.a, h.a);

            // Test scalar mul assign.
            let mut v = f.clone();
            v *= s.clone();
            assert_eq!(v.a, h.a);

            let mut v = f.clone();
            v *= &s.clone();
            assert_eq!(v.a, h.a);
        }
    }

    #[test]
    pub fn test_sum() {
        let test_cases = vec![
            // One.
            (vec![vec![1, 2, 3]], vec![1, 2, 3]),
            // Many.
            (vec![vec![1, 2, 3], vec![2, 4], vec![3]], vec![6, 6, 3]),
        ];

        for (coefficients_ps, coefficients_h) in test_cases {
            let ps: Vec<_> = coefficients_ps
                .iter()
                .map(|s| Polynomial::with_coefficients(scalars(s)))
                .collect();
            let h = Polynomial::with_coefficients(scalars(&coefficients_h));

            // Sum references.
            let v = ps.iter().sum::<Polynomial>();
            assert_eq!(v.a, h.a);

            // Sum values.
            let v = ps.into_iter().sum::<Polynomial>();
            assert_eq!(v.a, h.a);
        }
    }
}
