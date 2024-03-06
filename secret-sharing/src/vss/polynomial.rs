use std::{
    cmp::{max, min},
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign},
};

use group::ff::PrimeField;
use rand_core::RngCore;

use super::arith::powers;

/// Univariate polynomial over a non-binary prime field.
///
/// ```text
/// A(x) = \sum_{i=0}^{deg_x} a_i x^i
/// ```
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

/// Bivariate polynomial over a non-binary prime field.
///
/// ```text
/// B(x,y) = \sum_{i=0}^{deg_x} \sum_{j=0}^{deg_y} b_{i,j} x^i y^j
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
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
        self.b[0][0] == Fp::ZERO
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

    /// Evaluates the bivariate polynomial with respect to the indeterminate x.
    pub fn eval_x(&self, x: &Fp) -> Polynomial<Fp> {
        let xpows = powers(x, self.deg_x);
        let mut a = Vec::with_capacity(self.deg_y + 1);
        for yj in 0..=self.deg_y {
            let mut aj = Fp::ZERO;
            for (xi, pow) in xpows.iter().enumerate() {
                aj += self.b[xi][yj] * pow
            }
            a.push(aj)
        }

        Polynomial::with_coefficients(a)
    }

    /// Evaluates the bivariate polynomial with respect to the indeterminate y.
    pub fn eval_y(&self, y: &Fp) -> Polynomial<Fp> {
        let ypows = powers(y, self.deg_y);
        let mut a = Vec::with_capacity(self.deg_x + 1);
        for xi in 0..=self.deg_x {
            let mut ai = Fp::ZERO;
            for (yj, pow) in ypows.iter().enumerate() {
                ai += self.b[xi][yj] * pow
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

    #[test]
    fn test_p_zero() {
        let x0 = p384::Scalar::ZERO;

        let p = Polynomial::<p384::Scalar>::zero(0);
        assert_eq!(p.a, vec![x0]);

        let p = Polynomial::<p384::Scalar>::zero(2);
        assert_eq!(p.a, vec![x0, x0, x0]);
    }

    #[test]
    fn test_p_with_coefficients() {
        let x0 = p384::Scalar::ZERO;
        let x1 = p384::Scalar::from_u64(1);
        let x2 = p384::Scalar::from_u64(2);
        let x3 = p384::Scalar::from_u64(3);
        let a = vec![x1, x2, x3];

        let p = Polynomial::<p384::Scalar>::with_coefficients(vec![]);
        assert_eq!(p.a, vec![x0]);

        let p = Polynomial::<p384::Scalar>::with_coefficients(a.clone());
        assert_eq!(p.a, a);
    }

    #[test]
    fn test_p_serialization() {
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
    pub fn test_p_add() {
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
    pub fn test_p_add_assign() {
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
    pub fn test_p_sub() {
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
    pub fn test_p_sub_assign() {
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
    pub fn test_p_mul() {
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
    pub fn test_p_mul_assign() {
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
    pub fn test_p_scalar_mul() {
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
    pub fn test_p_scalar_mul_assign() {
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
    pub fn test_p_sum() {
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

    #[test]
    fn test_bp_zero() {
        let bp = BivariatePolynomial::<p384::Scalar>::zero(0, 0);
        assert_eq!(bp.deg_x, 0);
        assert_eq!(bp.deg_y, 0);
        assert_eq!(bp.b.len(), 1);
        assert_eq!(bp.b[0].len(), 1);
        assert_eq!(bp.b[0][0], p384::Scalar::ZERO);

        let bp = BivariatePolynomial::<p384::Scalar>::zero(2, 3);
        assert_eq!(bp.deg_x, 2);
        assert_eq!(bp.deg_y, 3);
        assert_eq!(bp.b.len(), 3);
        for bi in bp.b.iter() {
            assert_eq!(bi.len(), 4);
            for bij in bi.iter() {
                assert_eq!(bij, &p384::Scalar::ZERO);
            }
        }
    }

    #[test]
    fn test_bp_with_coefficients() {
        let x0 = p384::Scalar::ZERO;
        let x1 = p384::Scalar::from_u64(1);
        let x2 = p384::Scalar::from_u64(2);
        let x3 = p384::Scalar::from_u64(3);
        let b = vec![vec![x1, x2, x3], vec![x2, x3, x1]];

        let bp = BivariatePolynomial::<p384::Scalar>::with_coefficients(vec![]);
        assert_eq!(bp.deg_x, 0);
        assert_eq!(bp.deg_y, 0);
        assert_eq!(bp.b, vec![vec![x0]]);

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
                vec![x1, x2],
                vec![x1],
            ]);
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_bp_random() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let bp = BivariatePolynomial::<p384::Scalar>::random(0, 0, &mut rng);
        assert_eq!(bp.deg_x, 0);
        assert_eq!(bp.deg_y, 0);
        assert_eq!(bp.b.len(), 1);
        assert_eq!(bp.b[0].len(), 1);
        assert_ne!(bp.b[0][0], p384::Scalar::ZERO); // Zero with negligible probability.

        let bp = BivariatePolynomial::<p384::Scalar>::random(2, 3, &mut rng);
        assert_eq!(bp.deg_x, 2);
        assert_eq!(bp.deg_y, 3);
        assert_eq!(bp.b.len(), 3);
        for bi in bp.b.iter() {
            assert_eq!(bi.len(), 4);
            for bij in bi.iter() {
                assert_ne!(bij, &p384::Scalar::ZERO); // Zero with negligible probability.
            }
        }
    }

    #[test]
    fn test_bp_set_coefficient() {
        let mut bp = BivariatePolynomial::<p384::Scalar>::zero(2, 3);
        assert_eq!(bp.b[0][0], p384::Scalar::ZERO);

        bp.set_coefficient(p384::Scalar::ONE, 0, 0);
        assert_eq!(bp.b[0][0], p384::Scalar::ONE);
    }

    #[test]
    fn test_bp_to_zero_hole() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut bp = BivariatePolynomial::random(2, 3, &mut rng);

        bp.set_coefficient(p384::Scalar::ONE, 0, 0);
        assert_eq!(bp.b[0][0], p384::Scalar::ONE);

        bp.to_zero_hole();
        assert_eq!(bp.b[0][0], p384::Scalar::ZERO);
    }

    #[test]
    fn test_bp_serialization() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let bp = BivariatePolynomial::<p384::Scalar>::random(0, 0, &mut rng);
        let restored = BivariatePolynomial::<p384::Scalar>::from_bytes(bp.to_bytes())
            .expect("deserialization should succeed");
        assert_eq!(bp, restored);

        let bp = BivariatePolynomial::<p384::Scalar>::random(2, 3, &mut rng);
        let restored = BivariatePolynomial::<p384::Scalar>::from_bytes(bp.to_bytes())
            .expect("deserialization should succeed");
        assert_eq!(bp, restored);
    }

    #[test]
    fn test_bp_coefficient_byte_size() {
        let size = BivariatePolynomial::<p384::Scalar>::coefficient_byte_size();
        assert_eq!(size, 48);
    }

    #[test]
    fn test_bp_byte_size() {
        let size = BivariatePolynomial::<p384::Scalar>::byte_size(2, 3);
        assert_eq!(size, 2 + 3 * 4 * 48);
    }

    #[test]
    fn test_bp_eval() {
        let x1 = p384::Scalar::from_u64(1);
        let x2 = p384::Scalar::from_u64(2);
        let x3 = p384::Scalar::from_u64(3);
        let x4 = p384::Scalar::from_u64(4);
        let x5 = p384::Scalar::from_u64(5);
        let x48 = p384::Scalar::from_u64(48);
        let x59 = p384::Scalar::from_u64(59);
        let x86 = p384::Scalar::from_u64(86);
        let x117 = p384::Scalar::from_u64(117);
        let x242 = p384::Scalar::from_u64(242);
        let x298 = p384::Scalar::from_u64(298);
        let x586 = p384::Scalar::from_u64(586);

        let b = vec![vec![x1]];
        let bp = BivariatePolynomial::with_coefficients(b);

        let result = bp.eval_x(&x5);
        let expected = Polynomial::with_coefficients(vec![x1]);
        assert_eq!(result, expected);

        let result = bp.eval_y(&x5);
        let expected = Polynomial::with_coefficients(vec![x1]);
        assert_eq!(result, expected);

        let b = vec![
            vec![x1, x2, x3, x4],
            vec![x2, x3, x4, x1],
            vec![x3, x4, x1, x2],
        ];
        let bp = BivariatePolynomial::with_coefficients(b);

        let result = bp.eval_x(&x5);
        let expected = Polynomial::with_coefficients(vec![x86, x117, x48, x59]);
        assert_eq!(result, expected);

        let result = bp.eval_y(&x5);
        let expected = Polynomial::with_coefficients(vec![x586, x242, x298]);
        assert_eq!(result, expected);
    }
}
