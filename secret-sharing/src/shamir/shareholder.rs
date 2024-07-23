use group::ff::PrimeField;

use crate::{kdc::PointShareholder, poly::Point};

/// A holder of a secret share.
pub struct Shareholder<F> {
    /// Secret share point of the shared secret.
    share: Point<F>,
}

impl<F> Shareholder<F> {
    /// Creates a new shareholder with the given secret share.
    pub fn new(share: Point<F>) -> Self {
        Self { share }
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
