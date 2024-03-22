//! CHURP dealer.

use anyhow::{anyhow, Result};

use group::{
    ff::{Field, PrimeField},
    Group, GroupEncoding,
};
use rand_core::RngCore;

use crate::vss::{
    matrix::VerificationMatrix,
    polynomial::{BivariatePolynomial, Polynomial},
};

use super::Error;

/// Shareholder identifier.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct Shareholder(pub [u8; 32]);

/// Dealer parameters.
pub trait DealerParams {
    /// A prime field used for constructing the bivariate polynomial.
    type PrimeField: PrimeField;

    /// A group used for constructing the verification matrix.
    type Group: Group<Scalar = Self::PrimeField> + GroupEncoding;

    /// Maps given shareholder ID to a non-zero element of the prime field.
    fn encode(id: Shareholder) -> Result<Self::PrimeField>;
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
    /// Creates a new dealer.
    pub fn new(threshold: u8, dealing_phase: bool, rng: &mut impl RngCore) -> Self {
        let dx = threshold.saturating_sub(1); // Handle threshold 0 as 1.
        let dy = 2 * dx;

        match dealing_phase {
            true => Dealer::random(dx, dy, rng),
            false => Dealer::zero_hole(dx, dy, rng),
        }
    }

    /// Creates a new dealer from the given bivariate polynomial.
    pub fn from(bp: BivariatePolynomial<D::PrimeField>) -> Self {
        let vm = VerificationMatrix::new(&bp);
        Self { bp, vm }
    }

    /// Creates a new dealer with a random bivariate polynomial.
    fn random(dx: u8, dy: u8, rng: &mut impl RngCore) -> Self {
        let bp = BivariatePolynomial::random(dx, dy, rng);
        Self::from(bp)
    }

    /// Creates a new dealer with a random zero-hole bivariate polynomial.
    fn zero_hole(dx: u8, dy: u8, rng: &mut impl RngCore) -> Self {
        let mut bp = BivariatePolynomial::random(dx, dy, rng);
        bp.to_zero_hole();
        Self::from(bp)
    }

    /// Returns the secret bivariate polynomial.
    pub fn bivariate_polynomial(&self) -> &BivariatePolynomial<D::PrimeField> {
        &self.bp
    }

    /// Returns the verification matrix.
    pub fn verification_matrix(&self) -> &VerificationMatrix<D::Group> {
        &self.vm
    }

    // Returns a secret share for the given recipient.
    pub fn share(&self, recipient: &D::PrimeField) -> Result<Polynomial<D::PrimeField>> {
        if recipient.is_zero().into() {
            return Err(anyhow!("zero-value recipient not allowed"));
        }
        Ok(self.bp.eval_x(recipient))
    }
}

/// Dealer for NIST P-384's elliptic curve group.
pub type NistP384Dealer = Dealer<NistP384>;

/// NIST P-384 dealer parameters.
pub struct NistP384;

impl DealerParams for NistP384 {
    type PrimeField = p384::Scalar;
    type Group = p384::ProjectivePoint;

    fn encode(id: Shareholder) -> Result<Self::PrimeField> {
        let mut bytes = [0u8; 48];
        bytes[16..].copy_from_slice(&id.0);

        let s = p384::Scalar::from_slice(&bytes).or(Err(Error::ShareholderEncodingFailed))?;
        if s.is_zero().into() {
            return Err(Error::ZeroValueShareholder.into());
        }

        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::{BivariatePolynomial, DealerParams, Error, NistP384, NistP384Dealer, Shareholder};

    #[test]
    fn test_new() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let threshold = 3;
        for dealing_phase in vec![true, false] {
            let dealer = NistP384Dealer::new(threshold, dealing_phase, &mut rng);
            assert_eq!(dealer.verification_matrix().is_zero_hole(), !dealing_phase);
            assert_eq!(dealer.bivariate_polynomial().deg_x, 2);
            assert_eq!(dealer.bivariate_polynomial().deg_y, 4);
            assert_eq!(dealer.verification_matrix().rows, 3);
            assert_eq!(dealer.verification_matrix().cols, 5);
        }

        let threshold = 0;
        for dealing_phase in vec![true, false] {
            let dealer = NistP384Dealer::new(threshold, dealing_phase, &mut rng);
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
        let _ = NistP384Dealer::from(bp);
    }

    #[test]
    fn test_random() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let d = NistP384Dealer::random(2, 3, &mut rng);
        assert!(!d.verification_matrix().is_zero_hole()); // Zero-hole with negligible probability.
    }

    #[test]
    fn test_zero_hole() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let d = NistP384Dealer::zero_hole(2, 3, &mut rng);
        assert!(d.verification_matrix().is_zero_hole());
    }

    #[test]
    fn test_encode() {
        let id = [0; 32];
        let zero = NistP384::encode(Shareholder(id));
        assert!(zero.is_err());
        assert_eq!(
            zero.unwrap_err().to_string(),
            Error::ZeroValueShareholder.to_string()
        );

        let mut id = [0; 32];
        id[30] = 3;
        id[31] = 232;
        let thousand = NistP384::encode(Shareholder(id));
        assert!(thousand.is_ok());
        assert_eq!(thousand.unwrap(), p384::Scalar::from_u64(1000));
    }
}
