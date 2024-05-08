//! Helper functions to use with the asynchronous Tokio runtime.
use std::future::Future;

/// Create a new asynchronous Tokio runtime.
#[cfg(target_env = "sgx")]
pub fn new_tokio_runtime() -> tokio::runtime::Runtime {
    // In SGX use a trimmed-down version of the Tokio runtime.
    //
    // Make sure to update THREADS.md if you change any of the thread-related settings.
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(6)
        .max_blocking_threads(16)
        .thread_keep_alive(std::time::Duration::MAX)
        .enable_all()
        .build()
        .unwrap()
}

/// Create a new asynchronous Tokio runtime.
#[cfg(not(target_env = "sgx"))]
pub fn new_tokio_runtime() -> tokio::runtime::Runtime {
    // In non-SGX we use a fully-fledged Tokio runtime.
    tokio::runtime::Runtime::new().unwrap()
}

/// Runs a future to completion on the current Tokio handle's associated Runtime.
pub fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Handle::current().block_on(future)
}
