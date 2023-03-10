//! Helper functions to use with the asynchronous Tokio runtime.
use std::future::Future;

/// Runs a future to completion on the current Tokio handle's associated Runtime.
pub fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Handle::current().block_on(future)
}
