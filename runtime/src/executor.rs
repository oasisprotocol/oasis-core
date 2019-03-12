//! Single-threaded future executor.
use std::cell::RefCell;

use futures::prelude::*;
use tokio_current_thread::{CurrentThread, Entered, RunError, TaskExecutor};
use tokio_executor::{self, park::ParkThread};

thread_local! {
    static EXECUTOR: RefCell<Executor> = RefCell::new(Executor::new());
}

/// Single-threaded future executor.
pub struct Executor(CurrentThread);

impl Executor {
    /// Create a new executor.
    pub fn new() -> Self {
        Executor(CurrentThread::new())
    }

    /// Run a closure with the current thread-local executor.
    pub fn with_current<F, R>(f: F) -> R
    where
        F: FnOnce(&mut Executor) -> R,
    {
        EXECUTOR.with(|executor| f(&mut executor.borrow_mut()))
    }

    /// Spawn a future onto the executor.
    pub fn spawn<F>(&mut self, future: F) -> &mut Self
    where
        F: Future<Item = (), Error = ()> + 'static,
    {
        self.0.spawn(future);
        self
    }

    /// Runs the provided future, blocking the current thread until the future
    /// completes.
    ///
    /// This function can be used to synchronously block the current thread
    /// until the provided `future` has resolved either successfully or with an
    /// error. The result of the future is then returned from this function
    /// call.
    ///
    /// Note that this function will **also** execute any spawned futures on the
    /// current thread, but will **not** block until these other spawned futures
    /// have completed. Once the function returns, any uncompleted futures
    /// remain pending in the `Runtime` instance. These futures will not run
    /// until `block_on` or `run` is called again.
    ///
    /// The caller is responsible for ensuring that other spawned futures
    /// complete execution by calling `block_on` or `run`.
    pub fn block_on<F>(&mut self, f: F) -> Result<F::Item, F::Error>
    where
        F: Future,
    {
        self.enter(|executor| {
            // Run the provided future
            let ret = executor.block_on(f);
            ret.map_err(|e| e.into_inner().expect("unexpected execution error"))
        })
    }

    /// Run the executor to completion, blocking the thread until **all**
    /// spawned futures have completed.
    pub fn run(&mut self) -> Result<(), RunError> {
        self.enter(|executor| executor.run())
    }

    fn enter<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Entered<ParkThread>) -> R,
    {
        let executor = &mut self.0;

        // Binds an executor to this thread.
        let mut enter = tokio_executor::enter().expect("multiple executors at once");

        // The TaskExecutor is a fake executor that looks into the
        // current single-threaded executor when used. This is a trick,
        // because we need two mutable references to the executor (one
        // to run the provided future, another to install as the default
        // one). We use the fake one here as the default one.
        let mut default_executor = TaskExecutor::current();
        tokio_executor::with_default(&mut default_executor, &mut enter, |enter| {
            let mut executor = executor.enter(enter);
            f(&mut executor)
        })
    }
}
