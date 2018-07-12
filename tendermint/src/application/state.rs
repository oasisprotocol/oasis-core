//! Application state helpers.
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Helper for handling ABCI application state.
///
/// Tendermint requires three distinct states for the three different (concurrent)
/// connections that it establishes with the application.
pub struct ApplicationState<T> {
    /// State used during `deliver_tx` calls.
    deliver_tx: Mutex<T>,
    /// State used during `check_tx` calls.
    check_tx: Mutex<T>,
    /// Last committed state.
    commit: RwLock<T>,
}

impl<T> ApplicationState<T> {
    /// Create new application state.
    pub fn new() -> Self
    where
        T: Default,
    {
        Self {
            deliver_tx: Mutex::new(T::default()),
            check_tx: Mutex::new(T::default()),
            commit: RwLock::new(T::default()),
        }
    }

    /// Get state used during `deliver_tx` calls.
    pub fn get_deliver_tx<'a, 'b: 'a>(&'b self) -> MutexGuard<'a, T> {
        self.deliver_tx.lock().unwrap()
    }

    /// Get state used during `check_tx` calls.
    pub fn get_check_tx<'a, 'b: 'a>(&'b self) -> MutexGuard<'a, T> {
        self.check_tx.lock().unwrap()
    }

    /// Get last committed state for reading.
    pub fn get_commit_read<'a, 'b: 'a>(&'b self) -> RwLockReadGuard<'a, T> {
        self.commit.read().unwrap()
    }

    /// Get last committed state for writing.
    pub fn get_commit_write<'a, 'b: 'a>(&'b self) -> RwLockWriteGuard<'a, T> {
        self.commit.write().unwrap()
    }

    /// Makes current `deliver_tx` state the last committed state.
    pub fn commit(&self)
    where
        T: Clone,
    {
        let deliver_tx = self.deliver_tx.lock().unwrap();

        *self.check_tx.lock().unwrap() = deliver_tx.clone();
        *self.commit.write().unwrap() = deliver_tx.clone();
    }
}
