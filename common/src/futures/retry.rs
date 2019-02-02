#[cfg(not(target_env = "sgx"))]
use std::fmt::Debug;
#[cfg(not(target_env = "sgx"))]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(not(target_env = "sgx"))]
use std::sync::Arc;

#[cfg(not(target_env = "sgx"))]
use super::streamfollow;
#[cfg(not(target_env = "sgx"))]
use super::Stream;
use super::{super::error::Error, future, BoxFuture, Future, FutureExt};

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
    })
    .into_box()
}

/// Retry a future until success or a permanent error.
///
/// Retries `f` when an error is encountered, unless the error is "permanent," as
/// determined by `error_is_permanent`. Propagates permanent errors.
#[cfg(not(target_env = "sgx"))]
pub fn retry_until_ok<R, F, FP>(
    name: &'static str,
    mut f: F,
    error_is_permanent: FP,
) -> impl Future<Item = R::Item, Error = R::Error>
where
    R: Future,
    R::Error: Debug,
    F: FnMut() -> R,
    FP: Fn(&R::Error) -> bool,
{
    streamfollow::follow_skip(
        name,
        move || f().into_stream(),
        // Bookmark item is irelevant as there is always just a single item.
        |_item: &R::Item| "<retry_until_ok>",
        error_is_permanent,
    )
    .into_future()
    .map_err(|(error, _)| error)
    .map(|(result, _)| result.expect("item to be some"))
}

/// Retry a future until success or a permanent error or a maximum number of retries.
///
/// Retries `f` when an error is encountered, unless the error is "permanent," as
/// determined by `error_is_permanent`. Propagates permanent errors.
///
/// Additionally it considers an error "permanent" if `max_retries` retries is exceeded.
#[cfg(not(target_env = "sgx"))]
pub fn retry_until_ok_or_max<R, F, FP>(
    name: &'static str,
    f: F,
    error_is_permanent: FP,
    max_retries: usize,
) -> impl Future<Item = R::Item, Error = R::Error>
where
    R: Future,
    R::Error: Debug,
    F: FnMut() -> R,
    FP: Fn(&R::Error) -> bool,
{
    let retry_counter = Arc::new(AtomicUsize::new(0));

    retry_until_ok(name, f, move |error| {
        if error_is_permanent(error) || retry_counter.fetch_add(1, Ordering::SeqCst) > max_retries {
            return true;
        }

        false
    })
}
