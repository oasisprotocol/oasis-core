use group::Group;

use crate::poly::{powers, Polynomial};

/// Verification vector for a univariate polynomial.
///
/// The verification vector `V` is computed through scalar multiplication
/// of the coefficients of a univariate polynomial `P(x)` with a group
/// generator `G`.
///
/// Verification vector:
/// ```text
///     V = [a_i * G]
/// ```
///
/// Univariate polynomial:
/// ```text
///     P(x) = \sum_{i=0}^{deg_x} a_i x^i
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationVector<G>
where
    G: Group,
{
    /// The verification vector elements, where `v[i]` represents the element
    /// `a_i * G`.
    v: Vec<G>,
}

impl<G> VerificationVector<G>
where
    G: Group,
{
    /// Constructs a new verification vector.
    pub fn new(v: Vec<G>) -> Self {
        Self { v }
    }

    /// Verifies if the verification vector belongs to the given univariate
    /// polynomial.
    pub fn is_from(&self, p: &Polynomial<G::Scalar>) -> bool {
        if self.v.len() != p.a.len() {
            return false;
        }

        for (i, vi) in self.v.iter().enumerate() {
            let diff = G::generator() * p.a[i] - vi;
            if !Into::<bool>::into(diff.is_identity()) {
                return false;
            }
        }

        true
    }

    /// Verifies if the underlying univariate polynomial evaluates
    /// to the given value, i.e., if it holds `P(x) == v`.
    pub fn verify(&self, x: &G::Scalar, v: &G::Scalar) -> bool {
        let mut diff = G::generator().neg() * v;
        let xpows = powers(x, self.v.len() - 1); // [x^i]
        for (i, xpow) in xpows.into_iter().enumerate() {
            diff += self.v[i] * xpow; // x^i * V_i = a_i x^i * G
        }

        diff.is_identity().into()
    }
}

impl<G> From<&Polynomial<G::Scalar>> for VerificationVector<G>
where
    G: Group,
{
    /// Constructs a new verification vector from the given univariate
    /// polynomial.
    fn from(p: &Polynomial<G::Scalar>) -> Self {
        let mut v = Vec::with_capacity(p.size());
        for ai in p.a.iter() {
            v.push(G::generator() * ai)
        }

        Self::new(v)
    }
}

impl<G> From<Polynomial<G::Scalar>> for VerificationVector<G>
where
    G: Group,
{
    /// Constructs a new verification vector from the given univariate
    /// polynomial.
    fn from(p: Polynomial<G::Scalar>) -> Self {
        (&p).into()
    }
}

#[cfg(test)]
mod tests {
    use crate::{poly::Polynomial, vss::VerificationVector};

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
    fn test_from() {
        let p = Polynomial::<p384::Scalar>::with_coefficients(scalars(&vec![1, 2, 3]));
        let vv: VerificationVector<p384::ProjectivePoint> = VerificationVector::from(&p);
        assert_eq!(vv.v.len(), 3);
    }

    #[test]
    fn test_is_from() {
        let p = Polynomial::<p384::Scalar>::with_coefficients(scalars(&vec![1, 2, 3]));
        let q = Polynomial::<p384::Scalar>::with_coefficients(scalars(&vec![1, 0, 3]));
        let vv: VerificationVector<p384::ProjectivePoint> = VerificationVector::from(&p);
        assert!(vv.is_from(&p));
        assert!(!vv.is_from(&q));
    }

    #[test]
    fn test_verify() {
        let p = Polynomial::<p384::Scalar>::with_coefficients(scalars(&vec![1, 2, 3]));
        let vv: VerificationVector<p384::ProjectivePoint> = VerificationVector::from(&p);
        let x2 = scalar(2);
        let x3 = scalar(3);

        let s = p.eval(&x2);
        assert!(vv.verify(&x2, &s));
        assert!(!vv.verify(&x3, &s));
    }
}
