use ekiden_common::futures::BoxFuture;

use super::backend::StorageBackend;

/// A storage interface where writes are deferred. For backwards compatibility, it uses the
/// `StorageBackend` trait syntactically for `get` and `insert`. However, futures for write
/// operations may resolve before the data is persisted. This interface adds methods for
/// demarcating a batch of writes and waiting for them all to be persisted.
pub trait BatchStorage: StorageBackend {
    /// Start collecting a batch of writes. You can only collect into one batch at a time.
    fn start_batch(&self);
    /// Stop collecting the current batch of writes. Returns a future that resolves after the
    /// the writes in the batch are persisted.
    fn end_batch(&self) -> BoxFuture<()>;
}
