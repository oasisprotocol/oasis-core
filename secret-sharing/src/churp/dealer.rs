//! CHURP dealer.

use anyhow::Result;
use group::{ff::Field, Group, GroupEncoding};
use rand_core::RngCore;

use crate::{poly::BivariatePolynomial, vss::VerificationMatrix};

use super::{Error, HandoffKind, SecretShare};

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
    /// Creates a new dealer of secret bivariate shares, which can be used
    /// to recover a randomly selected shared secret.
    ///
    /// The dealer uses a random bivariate polynomial `B(x, y)` to generate
    /// full and reduced bivariate shares, i.e., `B(ID, y)` and `B(x, ID)`,
    /// where `ID` represents the identity of a participant, respectively.
    ///
    /// To ensure that the full and reduced bivariate shares form
    /// a (t, n)-sharing and a (2t, n)-sharing of the secret `B(0, 0)`,
    /// respectively, the bivariate polynomial is selected such that
    /// the polynomials `B(x, y)`, `B(x, 0)`, and `B(0, y)` have non-zero
    /// leading terms. This ensures that more than the threshold number
    /// of full shares, and more than twice the threshold number of reduced
    /// shares, are required to reconstruct the secret.
    ///
    /// Warning: If multiple dealers are used to generate the shared secret,
    /// it is essential to verify that the combined bivariate polynomial
    /// also satisfies the aforementioned non-zero leading term requirements.
    ///
    /// This function is not constant time because it uses rejection sampling.
    pub fn new(threshold: u8, rng: &mut impl RngCore) -> Result<Self> {
        let bp = Self::generate_bivariate_polynomial(threshold, rng)?;
        Ok(bp.into())
    }

    /// Creates a new dealer of secret proactive bivariate shares, which can
    /// be used to randomize a shared secret.
    ///
    /// The dealer uses a random zero-hole bivariate polynomial `B(x, y)`
    /// to generate full and reduced proactive bivariate shares, i.e.,
    /// `B(ID, y)` and `B(x, ID)`, where `ID` represents the identity
    /// of a participant. Since `B(0, 0) = 0`, adding a proactive share
    /// to an existing share does not change the shared secret.
    ///
    /// Warning: If one or more proactive dealers are used to randomize
    /// the shared secret, it is essential to verify that the combined
    /// bivariate polynomial still satisfies the non-zero leading term
    /// requirements.
    ///
    /// This function is not constant time because it uses rejection sampling.
    pub fn new_proactive(threshold: u8, rng: &mut impl RngCore) -> Result<Self> {
        let mut bp = Self::generate_bivariate_polynomial(threshold, rng)?;
        bp.to_zero_hole();
        Ok(bp.into())
    }

    /// Creates a new dealer of secret bivariate shares, which can be used
    /// to recover a predefined shared secret.
    ///
    /// This function is not constant time because it uses rejection sampling.
    #[cfg(test)]
    pub fn new_with_secret(
        threshold: u8,
        secret: G::Scalar,
        rng: &mut impl RngCore,
    ) -> Result<Self> {
        let mut bp = Self::generate_bivariate_polynomial(threshold, rng)?;
        let updated = bp.set_coefficient(0, 0, secret);
        debug_assert!(updated);
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

    /// Generates shares of the secret for the given shareholders.
    pub fn make_shares(
        &self,
        xs: Vec<G::Scalar>,
        kind: HandoffKind,
    ) -> Vec<SecretShare<G::Scalar>> {
        xs.into_iter().map(|x| self.make_share(x, kind)).collect()
    }

    /// Generates a share of the secret for the given shareholder.
    pub fn make_share(&self, x: G::Scalar, kind: HandoffKind) -> SecretShare<G::Scalar> {
        let p = match kind {
            HandoffKind::DealingPhase => self.bp.eval_x(&x),
            HandoffKind::CommitteeUnchanged => self.bp.eval_x(&x),
            HandoffKind::CommitteeChanged => self.bp.eval_y(&x),
        };

        SecretShare::new(x, p)
    }

    /// Generates a random bivariate polynomial `B(x, y)` such that
    /// the polynomials `B(x, y)`, `B(x, 0)`, and `B(0, y)` have non-zero
    /// leading term, and the secret `B(0, 0)` is non-zero.
    ///
    /// This function is not constant time because it uses rejection
    /// sampling to ensure that the polynomials have the maximum degree.
    /// Additionally, the underlying prime field implementation may also
    /// use rejection sampling to generate uniformly random elements.
    fn generate_bivariate_polynomial(
        threshold: u8,
        rng: &mut impl RngCore,
    ) -> Result<BivariatePolynomial<G::Scalar>> {
        let deg_x = threshold;
        let deg_y = threshold.checked_mul(2).ok_or(Error::ThresholdTooLarge)?;

        // When using a random RNG and a large prime field, this loop
        // should execute once with an extremely high probability,
        // so there is no need to optimize it by randomly selecting
        // only the problematic coefficients.
        for _ in 0..5 {
            let bp = BivariatePolynomial::<G::Scalar>::random(deg_x, deg_y, rng);

            let i = deg_x as usize;
            let j = deg_y as usize;
            let is_zero_00 = bp.coefficient(0, 0).unwrap().is_zero();
            let is_zero_xy = bp.coefficient(i, j).unwrap().is_zero();
            let is_zero_x0 = bp.coefficient(i, 0).unwrap().is_zero();
            let is_zero_0y = bp.coefficient(0, j).unwrap().is_zero();

            if (is_zero_00 | is_zero_xy | is_zero_x0 | is_zero_0y).into() {
                continue;
            }

            return Ok(bp);
        }

        Err(Error::PolynomialGenerationFailed.into())
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
    use rand::{rngs::StdRng, Error, RngCore, SeedableRng};

    use super::{BivariatePolynomial, HandoffKind};

    type PrimeField = p384::Scalar;
    type Group = p384::ProjectivePoint;
    type Dealer = super::Dealer<Group>;

    #[test]
    fn test_new() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let test_cases = vec![
            (0, 0, 0, 1, 1), // Zero threshold.
            (2, 2, 4, 3, 5), // Non-zero threshold.
        ];

        for (threshold, deg_x, deg_y, rows, cols) in test_cases {
            let dealer = Dealer::new(threshold, &mut rng).unwrap();
            assert_eq!(dealer.bivariate_polynomial().deg_x, deg_x);
            assert_eq!(dealer.bivariate_polynomial().deg_y, deg_y);
            assert_eq!(dealer.verification_matrix().rows, rows);
            assert_eq!(dealer.verification_matrix().cols, cols);
            assert_ne!(
                dealer.bivariate_polynomial().coefficient(0, 0), // Zero with negligible probability.
                Some(&PrimeField::ZERO)
            );
        }
    }

    #[test]
    fn test_new_proactive() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let test_cases = vec![
            (0, 0, 0, 1, 1), // Zero threshold.
            (2, 2, 4, 3, 5), // Non-zero threshold.
        ];

        for (threshold, deg_x, deg_y, rows, cols) in test_cases {
            let dealer = Dealer::new_proactive(threshold, &mut rng).unwrap();
            assert_eq!(dealer.bivariate_polynomial().deg_x, deg_x);
            assert_eq!(dealer.bivariate_polynomial().deg_y, deg_y);
            assert_eq!(dealer.verification_matrix().rows, rows);
            assert_eq!(dealer.verification_matrix().cols, cols);
            assert_eq!(
                dealer.bivariate_polynomial().coefficient(0, 0),
                Some(&PrimeField::ZERO)
            );
        }
    }

    #[test]
    fn test_new_with_secret() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let test_cases = vec![
            (0, 0, 0, 1, 1, 0),   // Zero threshold.
            (2, 2, 4, 3, 5, 100), // Non-zero threshold.
        ];

        for (threshold, deg_x, deg_y, rows, cols, secret) in test_cases {
            let secret = PrimeField::from_u64(secret);
            let dealer = Dealer::new_with_secret(threshold, secret, &mut rng).unwrap();
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
    fn test_make_share() {
        let threshold = 2;
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let dealer = Dealer::new(threshold, &mut rng).unwrap();
        let x = PrimeField::from_u64(2);

        let test_cases = vec![
            (HandoffKind::DealingPhase, 5),
            (HandoffKind::CommitteeUnchanged, 5),
            (HandoffKind::CommitteeChanged, 3),
        ];

        for (kind, size) in test_cases {
            let share = dealer.make_share(x, kind);
            assert_eq!(share.polynomial().size(), size);
        }
    }

    #[test]
    fn test_generate_bivariate_polynomial() {
        /// A custom RNG that fills the first few slices with zeros,
        /// and subsequent slices with ones.
        struct ZeroOneRng {
            /// Tracks how many times the RNG has been called.
            counter: usize,
            /// The number of slices that should be filled with zeros.
            limit: usize,
        }

        impl ZeroOneRng {
            /// Creates a new generator with the given limit.
            fn new(limit: usize) -> Self {
                Self { limit, counter: 0 }
            }

            // Returns the total number of times the generator has been invoked.
            fn total(&self) -> usize {
                self.counter
            }
        }

        impl RngCore for ZeroOneRng {
            fn next_u32(&mut self) -> u32 {
                panic!("not implemented")
            }

            fn next_u64(&mut self) -> u64 {
                panic!("not implemented")
            }

            fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Error> {
                panic!("not implemented")
            }

            fn fill_bytes(&mut self, dest: &mut [u8]) {
                match self.counter < self.limit {
                    true => dest.fill(0),
                    false => dest.fill(1),
                }
                self.counter += 1;
            }
        }

        let test_cases = vec![0, 2, 4];

        for threshold in test_cases {
            // Prepare RNG that will generate the first two bivariate polynomials
            // with all coefficients set to zero.
            let num_terms = (threshold + 1) * (2 * threshold + 1);
            let mut rng = ZeroOneRng::new(2 * num_terms);

            // Generate a random bivariate polynomial and verify leading coefficients.
            let bp = Dealer::generate_bivariate_polynomial(threshold as u8, &mut rng).unwrap();
            let f = bp.eval_y(&PrimeField::ZERO);
            let g = bp.eval_x(&PrimeField::ZERO);
            let i = threshold;
            let j = 2 * threshold;

            assert!(!Into::<bool>::into(bp.coefficient(i, j).unwrap().is_zero()));
            assert!(!Into::<bool>::into(f.coefficient(i).unwrap().is_zero()));
            assert!(!Into::<bool>::into(g.coefficient(j).unwrap().is_zero()));

            // Verify that the RNG generated coefficients for three polynomials.
            assert_eq!(3 * num_terms, rng.total());
        }
    }

    #[test]
    fn test_from() {
        let bp = BivariatePolynomial::zero(2, 3);
        let _ = Dealer::from(bp);
    }
}
