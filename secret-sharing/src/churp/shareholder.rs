//! CHURP shareholder.

use anyhow::Result;
use group::{ff::Field, Group, GroupEncoding};

use crate::{
    suites::Suite,
    vss::{matrix::VerificationMatrix, polynomial::Polynomial},
};

use crate::suites::FieldDigest;

use super::Error;

/// Domain separation tag for encoding shareholder identifiers.
const SHAREHOLDER_ENC_DST: &[u8] = b"shareholder";

/// Shareholder identifier.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct ShareholderId(pub [u8; 32]);

impl ShareholderId {
    /// Encodes the given shareholder ID to a non-zero element of the prime field.
    pub fn encode<H: FieldDigest>(&self) -> Result<H::Output> {
        let s = H::hash_to_field(&self.0[..], SHAREHOLDER_ENC_DST)
            .map_err(|_| Error::ShareholderEncodingFailed)?;

        if s.is_zero().into() {
            return Err(Error::ZeroValueShareholder.into());
        }

        Ok(s)
    }
}

/// Shareholder is responsible for deriving key shares and generating
/// switch points during handoffs when the committee is trying
/// to switch to the other dimension.
pub struct Shareholder<S: Suite> {
    /// Secret (full or reduced) share of the shared secret.
    share: SecretShare<S::Group>,
}

impl<S> Shareholder<S>
where
    S: Suite,
{
    /// Creates a new shareholder.
    pub fn new(p: Polynomial<S::PrimeField>, vm: VerificationMatrix<S::Group>) -> Self {
        SecretShare::new(p, vm).into()
    }

    /// Returns the secret share.
    pub fn secret_share(&self) -> &SecretShare<S::Group> {
        &self.share
    }

    /// Returns the polynomial.
    pub fn polynomial(&self) -> &Polynomial<S::PrimeField> {
        &self.share.p
    }

    /// Returns the verification matrix.
    pub fn verification_matrix(&self) -> &VerificationMatrix<S::Group> {
        &self.share.vm
    }

    /// Computes switch point for the given shareholder.
    pub fn switch_point(&self, id: ShareholderId) -> Result<S::PrimeField> {
        let x = id.encode::<S>()?;
        let point = self.share.p.eval(&x);
        Ok(point)
    }

    /// Computes key share from the given hash.
    pub fn key_share(&self, hash: S::Group) -> S::Group {
        self.share
            .p
            .coefficient(0)
            .map(|s| hash * s)
            .unwrap_or(S::Group::identity())
    }

    /// Creates a new shareholder with a proactivized secret polynomial.
    pub fn proactivize(
        &self,
        p: &Polynomial<S::PrimeField>,
        vm: &VerificationMatrix<S::Group>,
    ) -> Result<Shareholder<S>> {
        if p.degree() != self.share.p.degree() {
            return Err(Error::PolynomialDegreeMismatch.into());
        }
        if !vm.is_zero_hole() {
            return Err(Error::VerificationMatrixZeroHoleMismatch.into());
        }
        if vm.dimensions() != self.share.vm.dimensions() {
            return Err(Error::VerificationMatrixDimensionMismatch.into());
        }

        let p = p + &self.share.p;
        let vm = vm + &self.share.vm;
        let shareholder = Shareholder::new(p, vm);

        Ok(shareholder)
    }
}

impl<S> From<SecretShare<S::Group>> for Shareholder<S>
where
    S: Suite,
{
    fn from(share: SecretShare<S::Group>) -> Shareholder<S> {
        Shareholder { share }
    }
}

/// Secret share of the shared secret.
pub struct SecretShare<G>
where
    G: Group + GroupEncoding,
{
    /// Secret polynomial.
    p: Polynomial<G::Scalar>,

    /// Verification matrix.
    vm: VerificationMatrix<G>,
}

impl<G> SecretShare<G>
where
    G: Group + GroupEncoding,
{
    /// Creates a new secret share.
    pub fn new(p: Polynomial<G::Scalar>, vm: VerificationMatrix<G>) -> Self {
        Self { p, vm }
    }

    /// Returns the polynomial.
    pub fn polynomial(&self) -> &Polynomial<G::Scalar> {
        &self.p
    }

    /// Returns the verification matrix.
    pub fn verification_matrix(&self) -> &VerificationMatrix<G> {
        &self.vm
    }
}
