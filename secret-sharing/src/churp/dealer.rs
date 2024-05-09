//! CHURP dealer.

use anyhow::Result;
use group::{Group, GroupEncoding};
use rand_core::RngCore;

use crate::vss::{
    matrix::VerificationMatrix,
    polynomial::{BivariatePolynomial, Polynomial},
};

use super::{Error, HandoffKind};

/// Dealer is responsible for generating a secret bivariate polynomial,
/// computing a verification matrix, and deriving secret shares for other
/// participants.
///
/// Shares must always be distributed over a secure channel and verified
/// against the matrix. Recovering the secret bivariate polynomial requires
/// obtaining more than a threshold number of shares from distinct participants.
pub struct Dealer<G: Group + GroupEncoding> {
    /// Secret bivariate polynomial.
    bp: BivariatePolynomial<G::Scalar>,

    /// Verification matrix.
    vm: VerificationMatrix<G>,
}

impl<G> Dealer<G>
where
    G: Group + GroupEncoding,
{
    /// Creates a new dealer.
    pub fn new(threshold: u8, dealing_phase: bool, rng: &mut impl RngCore) -> Result<Self> {
        let dx = threshold;
        let dy = threshold.checked_mul(2).ok_or(Error::ThresholdTooLarge)?;

        let dealer = match dealing_phase {
            true => Dealer::random(dx, dy, rng),
            false => Dealer::zero_hole(dx, dy, rng),
        };

        Ok(dealer)
    }

    /// Creates a new dealer with a random bivariate polynomial.
    fn random(dx: u8, dy: u8, rng: &mut impl RngCore) -> Self {
        let bp = BivariatePolynomial::random(dx, dy, rng);
        bp.into()
    }

    /// Creates a new dealer with a random zero-hole bivariate polynomial.
    fn zero_hole(dx: u8, dy: u8, rng: &mut impl RngCore) -> Self {
        let mut bp = BivariatePolynomial::random(dx, dy, rng);
        bp.to_zero_hole();
        bp.into()
    }

    /// Returns the secret bivariate polynomial.
    pub fn bivariate_polynomial(&self) -> &BivariatePolynomial<G::Scalar> {
        &self.bp
    }

    /// Returns the verification matrix.
    pub fn verification_matrix(&self) -> &VerificationMatrix<G> {
        &self.vm
    }

    /// Returns a secret share for the given shareholder.
    pub fn derive_bivariate_share(
        &self,
        id: &G::Scalar,
        kind: HandoffKind,
    ) -> Polynomial<G::Scalar> {
        match kind {
            HandoffKind::DealingPhase => self.bp.eval_x(id),
            HandoffKind::CommitteeChanged => self.bp.eval_y(id),
            HandoffKind::CommitteeUnchanged => self.bp.eval_x(id),
        }
    }
}

impl<G> From<BivariatePolynomial<G::Scalar>> for Dealer<G>
where
    G: Group + GroupEncoding,
{
    /// Creates a new dealer from the given bivariate polynomial.
    fn from(bp: BivariatePolynomial<G::Scalar>) -> Self {
        let vm = VerificationMatrix::from(&bp);
        Self { bp, vm }
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::{BivariatePolynomial, HandoffKind};

    type PrimeField = p384::Scalar;
    type Group = p384::ProjectivePoint;
    type Dealer = super::Dealer<Group>;

    #[test]
    fn test_new() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let threshold = 2;
        for dealing_phase in vec![true, false] {
            let dealer = Dealer::new(threshold, dealing_phase, &mut rng).unwrap();
            assert_eq!(dealer.verification_matrix().is_zero_hole(), !dealing_phase);
            assert_eq!(dealer.bivariate_polynomial().deg_x, 2);
            assert_eq!(dealer.bivariate_polynomial().deg_y, 4);
            assert_eq!(dealer.verification_matrix().rows, 3);
            assert_eq!(dealer.verification_matrix().cols, 5);
        }

        let threshold = 0;
        for dealing_phase in vec![true, false] {
            let dealer = Dealer::new(threshold, dealing_phase, &mut rng).unwrap();
            assert_eq!(dealer.verification_matrix().is_zero_hole(), !dealing_phase);
            assert_eq!(dealer.bivariate_polynomial().deg_x, 0);
            assert_eq!(dealer.bivariate_polynomial().deg_y, 0);
            assert_eq!(dealer.verification_matrix().rows, 1);
            assert_eq!(dealer.verification_matrix().cols, 1);
        }
    }

    #[test]
    fn test_from() {
        let bp = BivariatePolynomial::zero(2, 3);
        let _ = Dealer::from(bp);
    }

    #[test]
    fn test_random() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let dealer = Dealer::random(2, 3, &mut rng);
        assert!(!dealer.verification_matrix().is_zero_hole()); // Zero-hole with negligible probability.
    }

    #[test]
    fn test_zero_hole() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let dealer = Dealer::zero_hole(2, 3, &mut rng);
        assert!(dealer.verification_matrix().is_zero_hole());
    }

    #[test]
    fn test_derive_bivariate_share() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let dealer = Dealer::random(2, 3, &mut rng);
        let id = PrimeField::from_u64(2);

        let p = dealer.derive_bivariate_share(&id, HandoffKind::DealingPhase);
        assert_eq!(p.degree(), 3);
        assert_eq!(p.size(), 4);

        let p = dealer.derive_bivariate_share(&id, HandoffKind::CommitteeChanged);
        assert_eq!(p.degree(), 2);
        assert_eq!(p.size(), 3);

        let p = dealer.derive_bivariate_share(&id, HandoffKind::CommitteeUnchanged);
        assert_eq!(p.degree(), 3);
        assert_eq!(p.size(), 4);
    }
}
