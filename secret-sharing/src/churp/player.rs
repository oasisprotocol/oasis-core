//! CHURP player.

use anyhow::Result;
use group::{Group, GroupEncoding};

use crate::{
    suites::Suite,
    vss::{matrix::VerificationMatrix, polynomial::Polynomial},
};

use super::{Error, ShareholderId};

/// Player is responsible for deriving key shares and generating
/// switch points during handoffs when the committee is trying
/// to switch to the other dimension.
pub struct Player<S: Suite> {
    /// Secret (full or reduced) share of the shared secret.
    share: SecretShare<S::Group>,
}

impl<S> Player<S>
where
    S: Suite,
{
    /// Creates a new player.
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

    /// Creates a new player with a proactivized secret polynomial.
    pub fn proactivize(
        &self,
        p: &Polynomial<S::PrimeField>,
        vm: &VerificationMatrix<S::Group>,
    ) -> Result<Player<S>> {
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
        let player = Player::new(p, vm);

        Ok(player)
    }
}

impl<S> From<SecretShare<S::Group>> for Player<S>
where
    S: Suite,
{
    fn from(state: SecretShare<S::Group>) -> Player<S> {
        Player { share: state }
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
