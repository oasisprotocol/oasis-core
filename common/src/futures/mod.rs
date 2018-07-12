//! Future types used in Ekiden.
extern crate futures as extern_futures;

pub use self::extern_futures::*;

use super::error::Error;

mod killable;
mod retry;
mod select_all;
#[cfg(not(target_env = "sgx"))]
mod spawn;

/// Future type for use in Ekiden.
pub type BoxFuture<T> = Box<Future<Item = T, Error = Error> + Send>;

/// Stream type for use in Ekiden.
pub type BoxStream<T> = Box<Stream<Item = T, Error = Error> + Send>;

/// Future trait with extra helper methods.
pub trait FutureExt: Future {
    #[cfg(target_env = "sgx")]
    fn wait(self) -> Result<Self::Item, Self::Error>
    where
        Self: Sized;

    /// Convenience function for turning this future into a trait object.
    fn into_box(self) -> Box<Future<Item = Self::Item, Error = Self::Error> + Send>
    where
        Self: Sized + Send + 'static,
    {
        Box::new(self)
    }

    /// Log errors produced by a future and discard them.
    fn log_errors_and_discard(
        self,
        log_target: &'static str,
        log_message: &'static str,
    ) -> Box<Future<Item = (), Error = ()> + Send>
    where
        Self: Sized + Send + 'static,
        Self::Error: ::std::fmt::Debug,
    {
        self.then(move |result| {
            if let Err(error) = result {
                warn!(target: log_target, "{}: {:?}", log_message, error);
            }

            future::ok(())
        }).into_box()
    }

    /// Discard item and error, returning a new future.
    fn discard(self) -> Box<Future<Item = (), Error = ()> + Send>
    where
        Self: Sized + Send + 'static,
    {
        self.map(|_| ()).map_err(|_| ()).into_box()
    }
}

impl<F: Future> FutureExt for F {
    #[cfg(target_env = "sgx")]
    fn wait(mut self) -> Result<Self::Item, Self::Error>
    where
        Self: Sized,
    {
        // Ekiden SGX enclaves are currently single-threaded and all OCALLs are blocking,
        // so nothing should return Async::NotReady.
        match self.poll() {
            Ok(Async::NotReady) => panic!("futures in SGX should always block"),
            Ok(Async::Ready(result)) => Ok(result),
            Err(error) => Err(error),
        }
    }
}

/// Stream trait with extra helper methods.
pub trait StreamExt: Stream {
    /// Convenience function for turning this stream into a trait object.
    fn into_box(self) -> Box<Stream<Item = Self::Item, Error = Self::Error> + Send>
    where
        Self: Sized + Send + 'static,
    {
        Box::new(self)
    }

    /// A wrapper for `for_each` which logs and discards all errors.
    ///
    /// This ensures that processing of the stream will continue even if errors are
    /// introduced.
    fn for_each_log_errors<F, U>(
        self,
        log_target: &'static str,
        log_message: &'static str,
        f: F,
    ) -> Box<Future<Item = (), Error = ()> + Send>
    where
        F: Fn(Self::Item) -> U + Send + 'static,
        U: FutureExt<Item = (), Error = Self::Error> + Send + 'static,
        Self: Sized + Send + 'static,
        Self::Error: ::std::fmt::Debug,
    {
        self.for_each(move |item| {
            f(item)
                .log_errors_and_discard(log_target, log_message)
                .map_err(|()| -> Self::Error {
                    unreachable!();
                })
        }).log_errors_and_discard(log_target, log_message)
    }
}

impl<S: Stream> StreamExt for S {}

pub use self::killable::{killable, KillHandle};
pub use self::retry::retry;
#[cfg(not(target_env = "sgx"))]
pub use self::spawn::*;

pub mod stream {
    pub use super::extern_futures::stream::*;

    // Backported functionality from futures 0.3.
    pub use super::select_all::*;
}

/// Common futures-related exports.
///
/// Should be imported as follows:
/// ```ignore
/// use ekiden_common::futures::prelude::*;
/// ```
pub mod prelude {
    pub use super::{future, stream, BoxFuture, BoxStream, Future, FutureExt, KillHandle, Sink,
                    Stream, StreamExt};

    #[cfg(not(target_env = "sgx"))]
    pub use super::{spawn, spawn_killable};
}
