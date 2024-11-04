//! CHURP shareholder.

use std::ops::AddAssign;

use anyhow::Result;
use group::{
    ff::{Field, PrimeField},
    Group,
};

use crate::{
    kdc::PointShareholder, poly::Polynomial, suites::FieldDigest, vss::VerificationMatrix,
};

use super::Error;

/// Encodes the given shareholder ID to a non-zero element of the prime field.
pub fn encode_shareholder<H: FieldDigest>(id: &[u8], dst: &[u8]) -> Result<H::Output> {
    let s = H::hash_to_field(id, dst).map_err(|_| Error::ShareholderEncodingFailed)?;

    if s.is_zero().into() {
        return Err(Error::ZeroValueShareholder.into());
    }

    Ok(s)
}

/// Shareholder is responsible for deriving key shares and generating
/// switch points during handoffs when the committee is trying
/// to switch to the other dimension.
pub struct Shareholder<G: Group> {
    /// Verifiable secret (full or reduced) share of the shared secret.
    verifiable_share: VerifiableSecretShare<G>,
}

impl<G> Shareholder<G>
where
    G: Group,
{
    /// Returns the verifiable secret share.
    pub fn verifiable_share(&self) -> &VerifiableSecretShare<G> {
        &self.verifiable_share
    }

    /// Computes switch point for the given shareholder.
    pub fn switch_point(&self, x: &G::Scalar) -> G::Scalar {
        self.verifiable_share.share.p.eval(x)
    }

    /// Creates a new shareholder with a proactivized secret polynomial.
    pub fn proactivize(
        &self,
        p: &Polynomial<G::Scalar>,
        vm: &VerificationMatrix<G>,
    ) -> Result<Shareholder<G>> {
        if p.size() != self.verifiable_share.share.p.size() {
            return Err(Error::PolynomialDegreeMismatch.into());
        }
        if !vm.is_zero_hole() {
            return Err(Error::VerificationMatrixZeroHoleMismatch.into());
        }
        if vm.dimensions() != self.verifiable_share.vm.dimensions() {
            return Err(Error::VerificationMatrixDimensionMismatch.into());
        }

        let x = self.verifiable_share.share.x;
        let p = p + &self.verifiable_share.share.p;
        let vm = vm + &self.verifiable_share.vm;
        let share = SecretShare::new(x, p);
        let verifiable_share = VerifiableSecretShare::new(share, vm);
        let shareholder = verifiable_share.into();

        Ok(shareholder)
    }
}

impl<G> From<VerifiableSecretShare<G>> for Shareholder<G>
where
    G: Group,
{
    fn from(verifiable_share: VerifiableSecretShare<G>) -> Shareholder<G> {
        Shareholder { verifiable_share }
    }
}

impl<G> PointShareholder<G::Scalar> for Shareholder<G>
where
    G: Group,
{
    fn coordinate_x(&self) -> &G::Scalar {
        self.verifiable_share.share.coordinate_x()
    }

    fn coordinate_y(&self) -> &G::Scalar {
        self.verifiable_share.share.coordinate_y()
    }
}

/// Secret share of the shared secret.
pub struct SecretShare<F: PrimeField> {
    /// The encoded identity of the shareholder.
    ///
    /// The identity is the x-coordinate of a point on the secret-sharing
    /// univariate polynomial B(x,0) or B(0,y).
    pub(crate) x: F,

    /// The secret polynomial B(id,y) or B(x,id).
    ///
    /// The constant term of the polynomial is the y-coordinate of a point
    /// on the secret-sharing univariate polynomial B(x,0) or B(0,y).
    pub(crate) p: Polynomial<F>,
}

impl<F> SecretShare<F>
where
    F: PrimeField,
{
    /// Creates a new secret share.
    pub fn new(x: F, p: Polynomial<F>) -> Self {
        Self { x, p }
    }

    /// Returns the polynomial.
    pub fn polynomial(&self) -> &Polynomial<F> {
        &self.p
    }

    /// Returns the x-coordinate of a point on the secret-sharing
    /// univariate polynomial B(x,0) or B(0,y).
    pub fn coordinate_x(&self) -> &F {
        &self.x
    }

    /// Returns the y-coordinate of a point on the secret-sharing
    /// univariate polynomial B(x,0) or B(0,y).
    pub fn coordinate_y(&self) -> &F {
        self.p
            .coefficient(0)
            .expect("polynomial has at least one term")
    }
}

impl<F> AddAssign for SecretShare<F>
where
    F: PrimeField,
{
    #[inline]
    fn add_assign(&mut self, rhs: SecretShare<F>) {
        *self += &rhs
    }
}

impl<F> AddAssign<&SecretShare<F>> for SecretShare<F>
where
    F: PrimeField,
{
    fn add_assign(&mut self, rhs: &SecretShare<F>) {
        debug_assert!(self.x == rhs.x);
        self.p += &rhs.p;
    }
}

/// Verifiable secret share of the shared secret.
pub struct VerifiableSecretShare<G: Group> {
    /// Secret (full or reduced) share of the shared secret.
    pub(crate) share: SecretShare<G::Scalar>,

    /// Verification matrix used to verify that the polynomial in the secret
    /// share is an evaluation B(x,id) or B(id,y) of the secret bivariate
    /// polynomial B(x,y).
    pub(crate) vm: VerificationMatrix<G>,
}

impl<G> VerifiableSecretShare<G>
where
    G: Group,
{
    /// Creates a new verifiable secret share.
    pub fn new(share: SecretShare<G::Scalar>, vm: VerificationMatrix<G>) -> Self {
        Self { share, vm }
    }

    /// Returns the secret share.
    pub fn secret_share(&self) -> &SecretShare<G::Scalar> {
        &self.share
    }

    /// Returns the verification matrix.
    pub fn verification_matrix(&self) -> &VerificationMatrix<G> {
        &self.vm
    }

    /// Verifies the secret share and the verification matrix.
    pub fn verify(&self, threshold: u8, zero_hole: bool, full_share: bool) -> Result<()> {
        self.verify_verification_matrix(threshold, zero_hole)?;
        self.verify_secret_share(threshold, full_share)?;
        Ok(())
    }

    /// Verifies the verification matrix.
    fn verify_verification_matrix(&self, threshold: u8, zero_hole: bool) -> Result<()> {
        let (rows, cols) = Self::calculate_dimensions(threshold);

        if self.vm.dimensions() != (rows, cols) {
            return Err(Error::VerificationMatrixDimensionMismatch.into());
        }
        if self.vm.is_zero_hole() != zero_hole {
            return Err(Error::VerificationMatrixZeroHoleMismatch.into());
        }

        // Verify that the bivariate polynomial `B(x, y)`, from which
        // the verification matrix was constructed and the share was derived,
        // satisfies the non-zero leading term requirements. Specifically,
        // the polynomials `B(x, y)`, `B(x, 0)`, and `B(0, y)` must have
        // non-zero leading terms.
        if threshold > 0 {
            // Skipping the special case where the bivariate polynomial has only
            // one coefficient. The verification of this coefficient has already
            // been done above, when we checked if the verification matrix
            // is zero-hole.
            let i = rows - 1;
            let j = cols - 1;

            if self.vm.element(i, j).unwrap().is_identity().into() {
                return Err(Error::InsecureBivariatePolynomial.into());
            }
            if self.vm.element(i, 0).unwrap().is_identity().into() {
                return Err(Error::InsecureBivariatePolynomial.into());
            }
            if self.vm.element(0, j).unwrap().is_identity().into() {
                return Err(Error::InsecureBivariatePolynomial.into());
            }
        }

        Ok(())
    }

    /// Verifies the secret share.
    fn verify_secret_share(&self, threshold: u8, full_share: bool) -> Result<()> {
        let (rows, cols) = Self::calculate_dimensions(threshold);

        if full_share {
            if self.share.p.size() != cols {
                return Err(Error::PolynomialDegreeMismatch.into());
            }
            if !self.vm.verify_x(&self.share.x, &self.share.p) {
                return Err(Error::InvalidPolynomial.into());
            }
        } else {
            if self.share.p.size() != rows {
                return Err(Error::PolynomialDegreeMismatch.into());
            }
            if !self.vm.verify_y(&self.share.x, &self.share.p) {
                return Err(Error::InvalidPolynomial.into());
            }
        }

        Ok(())
    }

    /// Calculates the number of rows and columns in the verification matrix
    /// based on the given threshold.
    const fn calculate_dimensions(threshold: u8) -> (usize, usize) {
        let rows: usize = threshold as usize + 1;
        let cols = threshold as usize * 2 + 1;
        (rows, cols)
    }
}

impl<G> AddAssign for VerifiableSecretShare<G>
where
    G: Group,
{
    #[inline]
    fn add_assign(&mut self, rhs: VerifiableSecretShare<G>) {
        *self += &rhs
    }
}

impl<G> AddAssign<&VerifiableSecretShare<G>> for VerifiableSecretShare<G>
where
    G: Group,
{
    fn add_assign(&mut self, rhs: &VerifiableSecretShare<G>) {
        self.share += &rhs.share;
        self.vm += &rhs.vm;
    }
}
