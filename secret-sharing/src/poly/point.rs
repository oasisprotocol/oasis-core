use group::{ff::PrimeField, Group};

/// A point (x,y) on a univariate polynomial f(x), where y = f(x).
#[derive(Clone)]
pub struct Point<F: PrimeField> {
    /// The x-coordinate of the point.
    pub(crate) x: F,
    /// The y-coordinate of the point.
    pub(crate) y: F,
}

impl<F> Point<F>
where
    F: PrimeField,
{
    /// Creates a new point.
    pub fn new(x: F, y: F) -> Self {
        Self { x, y }
    }
}

/// A point (x,y) on a univariate polynomial f(x), where y = f(x),
/// with an encrypted y-coordinate.
///
/// The y-coordinate is encrypted as z = y * P, where P is typically
/// a hash of an arbitrary-length byte string, e.g., P = H(id).
#[derive(Clone)]
pub struct EncryptedPoint<G: Group> {
    /// The x-coordinate of the point.
    pub(crate) x: G::Scalar,
    /// The y-coordinate of the point in encrypted form.
    pub(crate) z: G,
}

impl<G: Group> EncryptedPoint<G> {
    /// Creates a new encrypted point.
    pub fn new(x: G::Scalar, z: G) -> Self {
        Self { x, z }
    }

    /// Returns the x-coordinate of the point.
    pub fn x(&self) -> &G::Scalar {
        &self.x
    }

    /// Returns the y-coordinate of the point in encrypted form.
    pub fn z(&self) -> &G {
        &self.z
    }
}
