use super::super::error::Error;
use super::{future, BoxFuture, Future, FutureExt};

/// Retry a future up to maximum number of retries.
///
/// The retry function is called on each retry to produce a future. If the future
/// resolves to an error, it is retried again unless the maximum number of retries
/// has been reached. In this case, the error itself is returned.
pub fn retry<F, R>(max_retries: usize, f: F) -> BoxFuture<R::Item>
where
    F: Fn() -> R + Send + 'static,
    R: Future + Send + 'static,
    R::Item: Send,
    R::Error: ::std::fmt::Display + Send,
{
    future::loop_fn(max_retries, move |retries| {
        f().and_then(|result| Ok(future::Loop::Break(result)))
            .or_else(move |error| {
                if retries == 0 {
                    return Err(Error::new(format!("{}", error)));
                }

                Ok(future::Loop::Continue(retries - 1))
            })
    }).into_box()
}
