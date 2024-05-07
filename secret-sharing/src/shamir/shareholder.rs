use crate::vss::polynomial::Point;

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
