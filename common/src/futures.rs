//! Future types used in Ekiden.
#[cfg(not(target_env = "sgx"))]
use std::sync::Arc;

extern crate futures as extern_futures;
#[cfg(not(target_env = "sgx"))]
pub extern crate futures_cpupool as cpupool;

pub use self::extern_futures::*;
#[cfg(not(target_env = "sgx"))]
use self::future::Executor as OldExecutor;

use super::error::Error;

#[cfg(not(target_env = "sgx"))]
use grpcio;

/// Future type for use in Ekiden.
pub type BoxFuture<T> = Box<Future<Item = T, Error = Error> + Send>;

/// Stream type for use in Ekiden.
pub type BoxStream<T> = Box<Stream<Item = T, Error = Error> + Send>;

/// A task executor.
///
/// # Note
///
/// Once we transition to futures 0.2+ this trait will no longer be needed as there
/// is already a similar trait there.
pub trait Executor {
    /// Spawn the given task, polling it until completion.
    fn spawn(&mut self, f: Box<Future<Item = (), Error = ()> + Send>);
}

#[cfg(not(target_env = "sgx"))]
impl Executor for cpupool::CpuPool {
    fn spawn(&mut self, f: Box<Future<Item = (), Error = ()> + Send>) {
        self.execute(f).unwrap();
    }
}

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

/// Executor that uses the gRPC environment for execution.
#[cfg(not(target_env = "sgx"))]
pub struct GrpcExecutor(grpcio::Client);

#[cfg(not(target_env = "sgx"))]
impl GrpcExecutor {
    pub fn new(environment: Arc<grpcio::Environment>) -> Self {
        GrpcExecutor(
            // Create a dummy channel, needed for executing futures. This is required because
            // the API for doing this directly using an Executor is not exposed.
            grpcio::Client::new(grpcio::ChannelBuilder::new(environment).connect("")),
        )
    }
}

#[cfg(not(target_env = "sgx"))]
impl Executor for GrpcExecutor {
    fn spawn(&mut self, f: Box<Future<Item = (), Error = ()> + Send>) {
        self.0.spawn(f);
    }
}

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
