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
    /// Creates a new dealer based on the provided parameters.
    ///
    /// A dealer for the dealing phase uses a random bivariate polynomial,
    /// otherwise, it uses a zero-holed bivariate polynomial.
    pub fn create(threshold: u8, dealing_phase: bool, rng: &mut impl RngCore) -> Result<Self> {
        match dealing_phase {
            true => Self::random(threshold, rng),
            false => Self::zero_hole(threshold, rng),
        }
    }

    /// Creates a new dealer with a predefined shared secret.
    pub fn new(threshold: u8, secret: G::Scalar, rng: &mut impl RngCore) -> Result<Self> {
        let mut bp = Self::random_bivariate_polynomial(threshold, rng)?;
        bp.set_coefficient(0, 0, secret);
        Ok(bp.into())
    }

    /// Creates a new dealer with a random bivariate polynomial.
    pub fn random(threshold: u8, rng: &mut impl RngCore) -> Result<Self> {
        let bp = Self::random_bivariate_polynomial(threshold, rng)?;
        Ok(bp.into())
    }

    /// Creates a new dealer with a random zero-hole bivariate polynomial.
    pub fn zero_hole(threshold: u8, rng: &mut impl RngCore) -> Result<Self> {
        let mut bp = Self::random_bivariate_polynomial(threshold, rng)?;
        bp.to_zero_hole();
        Ok(bp.into())
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

    /// Returns a random bivariate polynomial.
    fn random_bivariate_polynomial(
        threshold: u8,
        rng: &mut impl RngCore,
    ) -> Result<BivariatePolynomial<G::Scalar>> {
        let deg_x = threshold;
        let deg_y = threshold.checked_mul(2).ok_or(Error::ThresholdTooLarge)?;
        let bp = BivariatePolynomial::random(deg_x, deg_y, rng);
        Ok(bp)
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
    fn test_create() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let test_cases = vec![
            // Zero threshold.
            (0, 0, 0, 1, 1),
            // Non-zero threshold.
            (2, 2, 4, 3, 5),
        ];

        for (threshold, deg_x, deg_y, rows, cols) in test_cases {
            for dealing_phase in vec![true, false] {
                let dealer = Dealer::create(threshold, dealing_phase, &mut rng).unwrap();
                assert_eq!(dealer.bivariate_polynomial().deg_x, deg_x);
                assert_eq!(dealer.bivariate_polynomial().deg_y, deg_y);
                assert_eq!(dealer.verification_matrix().rows, rows);
                assert_eq!(dealer.verification_matrix().cols, cols);
                assert_eq!(dealer.verification_matrix().is_zero_hole(), !dealing_phase);
            }
        }
    }

    #[test]
    fn test_new() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let tcs = vec![
            // Zero threshold.
            (0, 0, 0, 0, 1, 1),
            // Non-zero threshold.
            (100, 2, 2, 4, 3, 5),
        ];

        for (secret, threshold, deg_x, deg_y, rows, cols) in tcs {
            let secret = PrimeField::from_u64(secret);
            let dealer = Dealer::new(threshold, secret, &mut rng).unwrap();
            assert_eq!(dealer.bivariate_polynomial().deg_x, deg_x);
            assert_eq!(dealer.bivariate_polynomial().deg_y, deg_y);
            assert_eq!(dealer.verification_matrix().rows, rows);
            assert_eq!(dealer.verification_matrix().cols, cols);
            assert_eq!(
                dealer.bivariate_polynomial().coefficient(0, 0),
                Some(&secret)
            );
        }
    }

    #[test]
    fn test_random() {
        let threshold = 2;
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let dealer = Dealer::random(threshold, &mut rng).unwrap();
        assert!(!dealer.verification_matrix().is_zero_hole()); // Zero-hole with negligible probability.
    }

    #[test]
    fn test_zero_hole() {
        let threshold = 2;
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let dealer = Dealer::zero_hole(threshold, &mut rng).unwrap();
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

    #[test]
    fn test_from() {
        let bp = BivariatePolynomial::zero(2, 3);
        let _ = Dealer::from(bp);
    }
}
