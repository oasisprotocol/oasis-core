//! CHURP player.

use anyhow::Result;
use group::{Group, GroupEncoding};

use crate::vss::{matrix::VerificationMatrix, polynomial::Polynomial};

use super::{DealerParams, Error, Shareholder};

/// Player is responsible for deriving key shares and generating
/// switch points during handoffs when the committee is trying
/// to switch to the other dimension.
pub struct Player<D: DealerParams> {
    /// Secret (full or reduced) share of the shared secret.
    share: SecretShare<D::Group>,
}

impl<D> Player<D>
where
    D: DealerParams,
{
    /// Creates a new player.
    pub fn new(p: Polynomial<D::PrimeField>, vm: VerificationMatrix<D::Group>) -> Self {
        SecretShare::new(p, vm).into()
    }

    /// Returns the secret share.
    pub fn secret_share(&self) -> &SecretShare<D::Group> {
        &self.share
    }

    /// Returns the polynomial.
    pub fn polynomial(&self) -> &Polynomial<D::PrimeField> {
        &self.share.p
    }

    /// Returns the verification matrix.
    pub fn verification_matrix(&self) -> &VerificationMatrix<D::Group> {
        &self.share.vm
    }

    /// Computes switch point for the given shareholder.
    pub fn switch_point(&self, id: Shareholder) -> Result<D::PrimeField> {
        let x: <D as DealerParams>::PrimeField = D::encode_shareholder(id)?;
        let point = self.share.p.eval(&x);
        Ok(point)
    }

    /// Computes key share from the given hash.
    pub fn key_share(&self, hash: D::Group) -> D::Group {
        self.share
            .p
            .coefficient(0)
            .map(|s| hash * s)
            .unwrap_or(D::Group::identity())
    }

    /// Creates a new player with a proactivized secret polynomial.
    pub fn proactivize(
        &self,
        p: &Polynomial<D::PrimeField>,
        vm: &VerificationMatrix<D::Group>,
    ) -> Result<Player<D>> {
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

impl<D> From<SecretShare<D::Group>> for Player<D>
where
    D: DealerParams,
{
    fn from(state: SecretShare<D::Group>) -> Player<D> {
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
