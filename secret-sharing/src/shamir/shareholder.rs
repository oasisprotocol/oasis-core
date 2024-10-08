use anyhow::{bail, Result};
use group::ff::PrimeField;

use crate::{kdc::PointShareholder, poly::Point};

/// A holder of a secret share.
pub struct Shareholder<F: PrimeField> {
    /// Secret share point of the shared secret.
    share: Point<F>,
}

impl<F> Shareholder<F>
where
    F: PrimeField,
{
    /// Creates a new shareholder with the given secret share.
    pub fn new(share: Point<F>) -> Self {
        Self { share }
    }

    /// Returns secret share.
    pub fn secret_share(&self) -> &Point<F> {
        &self.share
    }

    /// Proactively refreshes the secret share using proactive shares derived
    /// from zero-hole polynomials.
    ///
    /// In verifiable secret sharing, the shareholder must verify that the
    /// proactive shares were indeed derived from zero-hole polynomials.
    pub fn proactivize(&mut self, shares: &[Point<F>]) -> Result<()> {
        // Ensure all shares were derived for the correct shareholder.
        //
        // Can be short-circuit as x-coordinates don't contain sensitive data.
        if shares.iter().any(|share| share.x != self.share.x) {
            bail!("invalid proactive share");
        }

        // Proactivize the share.
        for share in shares {
            self.share.y += share.y;
        }

        Ok(())
    }
}

impl<F> PointShareholder<F> for Shareholder<F>
where
    F: PrimeField,
{
    fn coordinate_x(&self) -> &F {
        &self.share.x
    }

    fn coordinate_y(&self) -> &F {
        &self.share.y
    }
}
