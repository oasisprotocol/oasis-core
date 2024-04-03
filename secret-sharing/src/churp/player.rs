//! CHURP player.

use anyhow::Result;
use group::Group;

use crate::vss::{matrix::VerificationMatrix, polynomial::Polynomial};

use super::{DealerParams, Error, Shareholder};

/// Player is responsible for deriving key shares and generating
/// switch points during handoffs when the committee is trying
/// to switch to the other dimension.
pub struct Player<D: DealerParams> {
    /// Secret polynomial (share of the shared secret).
    p: Polynomial<D::PrimeField>,

    /// Verification matrix.
    vm: VerificationMatrix<D::Group>,
}

impl<D> Player<D>
where
    D: DealerParams,
{
    /// Creates a new player.
    pub fn new(p: Polynomial<D::PrimeField>, vm: VerificationMatrix<D::Group>) -> Self {
        Self { p, vm }
    }

    /// Returns the verification matrix.
    pub fn verification_matrix(&self) -> &VerificationMatrix<D::Group> {
        &self.vm
    }

    /// Computes switch point for the given shareholder.
    pub fn switch_point(&self, id: Shareholder) -> Result<D::PrimeField> {
        let x: <D as DealerParams>::PrimeField = D::encode_shareholder(id)?;
        let point = self.p.eval(&x);
        Ok(point)
    }

    /// Computes key share from the given hash.
    pub fn key_share(&self, hash: D::Group) -> D::Group {
        self.p
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
        if p.degree() != self.p.degree() {
            return Err(Error::PolynomialDegreeMismatch.into());
        }
        if !vm.is_zero_hole() {
            return Err(Error::VerificationMatrixZeroHoleMismatch.into());
        }
        if vm.dimensions() != self.vm.dimensions() {
            return Err(Error::VerificationMatrixDimensionMismatch.into());
        }

        let p = p + &self.p;
        let vm = vm + &self.vm;
        let player = Player::new(p, vm);

        Ok(player)
    }
}
