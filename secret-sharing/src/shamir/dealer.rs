use group::ff::PrimeField;
use rand::RngCore;

use crate::poly::{Point, Polynomial};

/// A holder of the secret-sharing polynomial responsible for generating
/// secret shares.
pub struct Dealer<F> {
    /// The secret-sharing polynomial where the coefficient of the constant
    /// term represents the shared secret.
    poly: Polynomial<F>,
}

impl<F> Dealer<F>
where
    F: PrimeField,
{
    /// Creates a new dealer with a predefined shared secret.
    pub fn new(threshold: u8, secret: F, rng: &mut impl RngCore) -> Self {
        let mut sharer = Self::random(threshold, rng);
        let updated = sharer.poly.set_coefficient(0, secret);
        debug_assert!(updated);
        sharer
    }

    /// Creates a new dealer with a random shared secret.
    pub fn random(threshold: u8, rng: &mut impl RngCore) -> Self {
        let deg = threshold;
        let poly = Polynomial::random(deg, rng);
        Self { poly }
    }

    /// Generates shares of the secret for the given shareholders.
    pub fn make_shares(&self, xs: Vec<F>) -> Vec<Point<F>> {
        xs.into_iter().map(|x| self.make_share(x)).collect()
    }

    /// Generates a share of the secret for the given shareholder.
    pub fn make_share(&self, x: F) -> Point<F> {
        let y = self.poly.eval(&x);
        Point::new(x, y)
    }
}
