//! Simple timer for measuring blocks.
use std::time::Instant;

/// A simple timer which invokes a given closure when dropped.
///
/// # Examples
///
/// ```ignore
/// let timer = Timer::new(|elapsed| println!("elapsed: {}", elapsed));
/// // ...
/// drop(timer);
/// ```
pub struct Timer<F: Fn(f64)> {
    start: Instant,
    collect: F,
}

impl<F: Fn(f64)> Timer<F> {
    /// Create a new `Timer`.
    pub fn new(collect: F) -> Self {
        Self {
            start: Instant::now(),
            collect,
        }
    }
}

impl<F: Fn(f64)> Drop for Timer<F> {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed();
        let elapsed = elapsed.as_secs() as f64 + elapsed.subsec_nanos() as f64 * 1e-9;

        (self.collect)(elapsed);
    }
}
