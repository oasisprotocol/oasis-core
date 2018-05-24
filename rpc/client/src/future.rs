use futures::future::Future;
use futures::Async;

use ekiden_common::error::Error;

/// Future type for use in client calls.
pub type ClientFuture<T> = Box<FutureExtra<Item = T, Error = Error> + Send>;

/// Future trait with extra helper methods.
pub trait FutureExtra: Future {
    fn wait(self) -> Result<Self::Item, Self::Error>
    where
        Self: Sized;
}

impl<F: Future> FutureExtra for F {
    fn wait(mut self) -> Result<Self::Item, Self::Error>
    where
        Self: Sized,
    {
        // Ekiden SGX enclaves are currently single-threaded and all OCALLs are blocking,
        // so nothing should return Async::NotReady.
        match self.poll() {
            Ok(Async::NotReady) => panic!("Futures in SGX should always block"),
            Ok(Async::Ready(result)) => Ok(result),
            Err(error) => Err(error),
        }
    }
}
