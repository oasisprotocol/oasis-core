use group::ff::PrimeField;
use rand::RngCore;

use crate::vss::polynomial::{Point, Polynomial};

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
        sharer.poly.set_coefficient(secret, 0);
        sharer
    }

    /// Creates a new dealer with a random shared secret.
    pub fn random(threshold: u8, rng: &mut impl RngCore) -> Self {
        let deg = threshold;
        let poly = Polynomial::random(deg, rng);
        Self { poly }
    }

    /// Proactively refreshes the secret polynomial.
    pub fn proactivize(&mut self, rng: &mut impl RngCore) {
        let deg = self.poly.size() - 1;
        let mut poly = Polynomial::random(deg as u8, rng);
        poly.to_zero_hole();
        self.poly += poly;
    }

    /// Generates shares of the secret for the given shareholders.
    pub fn make_shares(&self, xs: Vec<F>) -> Vec<Point<F>> {
        let mut shares = Vec::with_capacity(xs.len());
        for x in xs {
            let share = self.make_share(x);
            shares.push(share);
        }
        shares
    }

    /// Generates a share of the secret for the given shareholder.
    pub fn make_share(&self, x: F) -> Point<F> {
        let y = self.poly.eval(&x);
        Point::new(x, y)
    }
}
