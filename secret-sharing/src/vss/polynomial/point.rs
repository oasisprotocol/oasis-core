/// A point (x,y) on a univariate polynomial f(x), where y = f(x).
pub struct Point<F> {
    /// The x-coordinate of the point.
    pub(crate) x: F,
    /// The y-coordinate of the point.
    pub(crate) y: F,
}

impl<F> Point<F> {
    /// Creates a new point.
    pub fn new(x: F, y: F) -> Self {
        Self { x, y }
    }
}
