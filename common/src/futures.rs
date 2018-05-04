//! Future types used in Ekiden.
extern crate futures as extern_futures;
#[cfg(not(target_env = "sgx"))]
pub extern crate futures_cpupool as cpupool;

pub use self::extern_futures::*;
#[cfg(not(target_env = "sgx"))]
use self::future::Executor as OldExecutor;

use super::error::Error;

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
