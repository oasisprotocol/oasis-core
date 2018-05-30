//! A common structure for handling lists of subscribers.
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

use super::error::Error;
use super::futures::sync::mpsc;
use super::futures::{BoxStream, Stream};

/// Structure for keeping track of subscribers to a `Stream`.
pub struct StreamSubscribers<T> {
    inner: RwLock<HashMap<usize, mpsc::UnboundedSender<T>>>,
    last_id: AtomicUsize,
}

impl<T> StreamSubscribers<T> {
    /// Create a new stream subscribers structure.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            last_id: AtomicUsize::new(0),
        }
    }

    /// Send given value to all subscribers.
    ///
    /// Any subscribers that have gone away will be purged from the list.
    pub fn notify(&self, value: &T)
    where
        T: Clone,
    {
        // Send notifications and collect channels which have been closed.
        let closed_ids: Vec<usize> = {
            let inner = self.inner.read().unwrap();
            inner
                .iter()
                .filter(|&(_, subscriber)| subscriber.unbounded_send(value.clone()).is_err())
                .map(|(id, _)| *id)
                .collect()
        };

        // Cleanup any closed subscribers.
        {
            let mut inner = self.inner.write().unwrap();
            for id in closed_ids {
                inner.remove(&id);
            }
        }
    }

    /// Create a new subscriber.
    ///
    /// Returns a tuple `(sender, stream)`.
    ///
    /// The returned `sender` can be used to send initial subscriber-specific data to the
    /// new subscriber.
    pub fn subscribe(&self) -> (mpsc::UnboundedSender<T>, BoxStream<T>)
    where
        T: Send + 'static,
    {
        let (sender, receiver) = mpsc::unbounded();
        let id = self.last_id.fetch_add(1, Ordering::SeqCst);
        {
            let mut inner = self.inner.write().unwrap();
            inner.insert(id, sender.clone());
        }

        // Create BoxStream from receiver.
        let receiver = Box::new(receiver.map_err(|_| Error::new("channel closed")));

        (sender, receiver)
    }
}
