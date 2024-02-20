//! CHURP dealer.

use group::{ff::PrimeField, Group, GroupEncoding};
use rand_core::RngCore;

use crate::vss::{matrix::VerificationMatrix, polynomial::BivariatePolynomial};

/// Dealer parameters.
pub trait DealerParams {
    /// A prime field used for constructing the bivariate polynomial.
    type PrimeField: PrimeField;

    /// A group used for constructing the verification matrix.
    type Group: Group<Scalar = Self::PrimeField> + GroupEncoding;
}

/// Dealer is responsible for generating a secret bivariate polynomial,
/// computing a verification matrix, and deriving secret shares for other
/// participants.
///
/// Shares must always be distributed over a secure channel and verified
/// against the matrix. Reconstructing the secret bivariate polynomial
/// requires obtaining at least a threshold number of shares from distinct
/// participants.
#[derive(Debug, Clone)]
pub struct Dealer<D: DealerParams> {
    /// Secret bivariate polynomial.
    bp: BivariatePolynomial<D::PrimeField>,

    /// Verification matrix.
    vm: VerificationMatrix<D::Group>,
}

impl<D> Dealer<D>
where
    D: DealerParams,
{
    /// Creates a new dealer from the given bivariate polynomial.
    pub fn new(bp: BivariatePolynomial<D::PrimeField>) -> Self {
        let vm = VerificationMatrix::new(&bp);
        Self { bp, vm }
    }

    /// Creates a new dealer with a random bivariate polynomial.
    pub fn random(dx: u8, dy: u8, rng: &mut impl RngCore) -> Self {
        let bp = BivariatePolynomial::random(dx, dy, rng);
        Self::new(bp)
    }

    /// Creates a new dealer with a random zero-hole bivariate polynomial.
    pub fn zero_hole(dx: u8, dy: u8, rng: &mut impl RngCore) -> Self {
        let mut bp = BivariatePolynomial::random(dx, dy, rng);
        bp.to_zero_hole();
        Self::new(bp)
    }

    /// Returns the secret bivariate polynomial.
    pub fn bivariate_polynomial(&self) -> &BivariatePolynomial<D::PrimeField> {
        &self.bp
    }

    /// Returns the verification matrix.
    pub fn verification_matrix(&self) -> &VerificationMatrix<D::Group> {
        &self.vm
    }
}

/// Dealer for NIST P-384's elliptic curve group.
pub type NistP384Dealer = Dealer<NistP384>;

/// NIST P-384 dealer parameters.
pub struct NistP384;

impl DealerParams for NistP384 {
    type PrimeField = p384::Scalar;
    type Group = p384::ProjectivePoint;
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::{BivariatePolynomial, NistP384Dealer};

    #[test]
    fn test_new() {
        let bp = BivariatePolynomial::zero(2, 3);
        let _ = NistP384Dealer::new(bp);
    }

    #[test]
    fn test_random() {
        let d = NistP384Dealer::random(2, 3, &mut OsRng);
        assert!(!d.verification_matrix().is_zero_hole()); // Zero-hole with negligible probability.
    }

    #[test]
    fn test_zero_hole() {
        let d = NistP384Dealer::zero_hole(2, 3, &mut OsRng);
        assert!(d.verification_matrix().is_zero_hole());
    }
}
