//! Batch storage backend.
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use ekiden_common::bytes::H256;
use ekiden_common::environment::Environment;
use ekiden_common::error::Error;
use ekiden_common::futures::{self, BoxFuture, Future, FutureExt, Stream};
use ekiden_storage_base::{hash_storage_key, StorageBackend};

struct Inner {
    /// We do some writeback operations on the shared executor.
    env: Arc<Environment>,
    /// This map lets us answer consistently when we insert an item and try to get it before it is
    /// persisted.
    writeback: Arc<Mutex<HashMap<H256, Vec<u8>>>>,
    /// Forward requests to this.
    delegate: Arc<StorageBackend>,
    /// A channel for transferring errors from asynchronous writes to the flush call.
    error_tx: futures::sync::mpsc::UnboundedSender<Error>,
    /// A channel for transferring errors from asynchronous writes to the flush call.
    error_rx: futures::sync::mpsc::UnboundedReceiver<Error>,
}

/// This storage backend forwards calls to a delegate and makes inserts return successfully
/// immediately and performs them asynchronously. Call its `flush` method to disconnect from the
/// delegate and wait for asynchronous inserts to finish.
pub struct BatchStorageBackend {
    /// We cut this off when we flush, simulating the disposal of this object. We can't actually
    /// consume this backend because many consumers have an Arc of the backend instead of owning
    /// it.
    inner: RwLock<Option<Inner>>,
}

impl BatchStorageBackend {
    pub fn new(env: Arc<Environment>, delegate: Arc<StorageBackend>) -> Self {
        let (error_tx, error_rx) = futures::sync::mpsc::unbounded();
        BatchStorageBackend {
            inner: RwLock::new(Some(Inner {
                env,
                writeback: Arc::new(Mutex::new(HashMap::new())),
                delegate,
                error_tx,
                error_rx,
            })),
        }
    }

    /// Wait for inserts to be persisted to the delegate backend. Report any errors from inserts
    /// issued in this batch.
    pub fn flush(&self) -> BoxFuture<()> {
        self.inner
            .write()
            .unwrap()
            .take()
            .expect("BatchStorageBackend access after flush")
            .error_rx
            .collect()
            .then(|result| {
                let errors = result.unwrap();
                if errors.is_empty() {
                    Ok(())
                } else {
                    Err(Error::new(format!("Some inserts failed: {:?}", errors)))
                }
            })
            .into_box()
    }
}

impl StorageBackend for BatchStorageBackend {
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        let inner_guard = self.inner.read().unwrap();
        let inner = inner_guard
            .as_ref()
            .expect("BatchStorageBackend access after flush");
        if let Some(value) = inner.writeback.lock().unwrap().get(&key) {
            return futures::future::ok(value.clone()).into_box();
        }
        inner.delegate.get(key)
    }

    fn insert(&self, value: Vec<u8>, expiry: u64) -> BoxFuture<()> {
        let key = hash_storage_key(&value);
        let inner_guard = self.inner.read().unwrap();
        let inner = inner_guard
            .as_ref()
            .expect("BatchStorageBackend access after flush");
        let mut writeback_guard = inner.writeback.lock().unwrap();
        if writeback_guard.contains_key(&key) {
            warn!(
                "insert: tried to insert key {} which is already writeback. ignoring",
                key
            );
        } else {
            writeback_guard.insert(key, value.clone());
            let writeback = inner.writeback.clone();
            let error_tx = inner.error_tx.clone();
            inner.env.spawn(
                inner
                    .delegate
                    .insert(value, expiry)
                    .then(move |result| {
                        match result {
                            Ok(()) => {
                                writeback.lock().unwrap().remove(&key);
                            }
                            Err(error) => {
                                warn!(
                                    "insert: unable to persist key {} to delegate: {:?}",
                                    key, error
                                );
                                error_tx.unbounded_send(error).unwrap();
                                // Writeback entry remains, keeping storage consistent. But flush
                                // will fail.
                            }
                        }
                        Ok(())
                    })
                    .into_box(),
            );
        }
        futures::future::ok(()).into_box()
    }

    fn get_keys(&self) -> BoxFuture<Arc<Vec<(H256, u64)>>> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use ekiden_common;
    use ekiden_common::environment::GrpcEnvironment;
    use ekiden_common::futures::Future;
    use ekiden_storage_base::{hash_storage_key, StorageBackend};
    use ekiden_storage_dummy::DummyStorageBackend;
    extern crate grpcio;

    use BatchStorageBackend;

    #[test]
    fn test_batch() {
        ekiden_common::testing::try_init_logging();
        let grpc_environment = grpcio::EnvBuilder::new().build();
        let environment = Arc::new(GrpcEnvironment::new(grpc_environment));

        let delegate = Arc::new(DummyStorageBackend::new());

        {
            let batch = Arc::new(BatchStorageBackend::new(
                environment.clone(),
                delegate.clone(),
            ));
            let storage: Arc<StorageBackend> = batch.clone();

            let key = hash_storage_key(b"value");
            assert!(storage.get(key).wait().is_err());

            // Test that key is available immediately from same interface.
            storage.insert(b"value".to_vec(), 10).wait().unwrap();
            assert_eq!(storage.get(key).wait(), Ok(b"value".to_vec()));

            // Flush.
            batch.flush().wait().unwrap();

            // Test that key is available in delegate after committing.
            assert_eq!(delegate.get(key).wait(), Ok(b"value".to_vec()));
        }

        {
            let batch = Arc::new(BatchStorageBackend::new(
                environment.clone(),
                delegate.clone(),
            ));

            // Insert directly to delegate and expect to find it in this interface.
            let key = hash_storage_key(b"another");
            delegate.insert(b"another".to_vec(), 10).wait().unwrap();
            assert_eq!(batch.get(key).wait(), Ok(b"another".to_vec()));
        }
    }
}
