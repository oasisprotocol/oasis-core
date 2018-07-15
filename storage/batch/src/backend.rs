//! Batch storage backend.
use std;
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::H256;
use ekiden_common::futures::{self, stream, BoxFuture, Future, FutureExt, Stream};
use ekiden_common::futures::prelude::*;
use ekiden_common::environment::Environment;
use ekiden_storage_base::{hash_storage_key, StorageBackend};
use ekiden_storage_dummy::DummyStorageBackend;
use ekiden_epochtime::interface::TimeSourceNotifier;

struct Inner {
    /// Always-available backend to store uncommitted data.
    always_available: Arc<StorageBackend>,
    /// Storage backend for committed data.
    committed: Arc<StorageBackend>,
    /// Items inserted during the last transaction.
    inserts: Mutex<Vec<(H256, u64)>>,
    /// Maximum number of retries.
    retries: usize,
    /// Epoch information.
    time_notifier: Arc<TimeSourceNotifier>,
    /// Active key list.
    key_list: Mutex<Vec<(H256,u64)>>,
}

/// Virtual storage backend which processes a batch of inserts.
///
/// This storage backend uses two actual storage backends:
/// * The first is an always-available backend which is used to queue all inserts until
///   a `commit` is issued. Currently, this uses an in-memory storage backend.
/// * The second is backend is the actual backend where data should be committed to
///   after the batch has been processed and a `commit` issued.
///
/// All gets first hit the always-available backend and in case of missing keys, they
/// hit the committed backend.
pub struct BatchStorageBackend {
    inner: Arc<Inner>,
}

impl BatchStorageBackend {
    pub fn new(committed: Arc<StorageBackend>, retries: usize, time_notifier: Arc<TimeSourceNotifier>,environment: Arc<Environment> ) -> Self {
        let instance = Self {
            inner: Arc::new(Inner {
                // TODO: Should we use persistent storage instead of holding a batch in memory?
                always_available: Arc::new(DummyStorageBackend::new()),
                committed,
                inserts: Mutex::new(vec![]),
                retries,
                time_notifier,
                key_list: Mutex::new(vec![]),
            }),
        };
        instance.get_keys(environment);
        instance
    }

    pub fn get_keys(&self, environment: Arc<Environment>){
        environment.spawn({
            let shared_inner = self.inner.clone();
            Box::new(
                self.inner
                .time_notifier
                .watch_epochs()
                .for_each(move |_|{
                        let inserts = shared_inner.inserts.lock().unwrap();
                        let mut key_list = shared_inner.key_list.lock().unwrap();
                        let len = inserts.to_owned().len();
                        for i in 0..len{
                            let key_pair = &mut inserts.to_owned()[i];
                            println!("tracked key is {:?}",key_pair);
                            key_list.push(key_pair.to_owned());
                        }
                Ok(())
                })
                .then(|_| future::ok(())),
            )
        
        })
    }

    /// Commit all inserts to the committed backend.
    pub fn commit(&self) -> BoxFuture<()> {
        // Get insert log.
        let inserts = {
            let mut inserts = self.inner.inserts.lock().unwrap();
            std::mem::replace(&mut *inserts, vec![])
        };

        // Iterate over log and insert all values, with retry.
        let retries = self.inner.retries;
        let always_available = self.inner.always_available.clone();
        let committed = self.inner.committed.clone();

        stream::iter_ok(inserts.into_iter())
            .for_each(move |(key, expiry)| {
                let committed = committed.clone();

                always_available.get(key).and_then(move |value| {
                    futures::retry(retries, move || committed.insert(value.clone(), expiry))
                        .or_else(|error| {
                            warn!("Failed to commit to storage: {:?}", error);

                            Err(error)
                        })
                })
            })
            .into_box()
    }
}

impl StorageBackend for BatchStorageBackend {
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        let committed = self.inner.committed.clone();
        let retries = self.inner.retries;

        self.inner
            .always_available
            .get(key)
            .or_else(move |_error| futures::retry(retries, move || committed.get(key)))
            .into_box()
    }

    fn insert(&self, value: Vec<u8>, expiry: u64) -> BoxFuture<()> {
        let inner = self.inner.clone();
        let key = hash_storage_key(&value);

        self.inner
            .always_available
            .insert(value, expiry)
            .and_then(move |_| {
                let mut inserts = inner.inserts.lock().unwrap();
                inserts.push((key, expiry));
                Ok(())
            })
            .into_box()
    }

    fn get_key_list(&self) -> Vec<(H256, u64)>{
        let inner = self.inner.clone();
        let inserts = inner.inserts.lock().unwrap();
        println!("Get Key List is: {:?}", *inserts);
/*        
        let time_notifier = inner.time_notifier.clone();
        let epoch_stream = time_notifier.watch_epochs();

        let mut key_list = inner.key_list.lock().unwrap();

        epoch_stream
            .for_each(move|_| {
                key_list.clear();
                let len = inserts.to_owned().len();
//                let mut key_list = inner.key_list.lock().unwrap();
                for i in 0..len {
                    println!("tracked key is {:?}",inserts.to_owned()[i]);
                    let key_pair = &mut inserts.to_owned()[i];
                    &mut key_list.push(key_pair.to_owned());
                }
                Ok(())
            });
*/
        let key = hash_storage_key(b"value");
        let mut x = Vec::new();
        x.push((key, 10));
        return x;
    }
}

#[cfg(test)]
mod test {
    extern crate grpcio;
    use std::sync::Arc;
    use ekiden_common::environment::GrpcEnvironment;
    use ekiden_epochtime::interface::EPOCH_INTERVAL;
    use ekiden_epochtime::local::{LocalTimeSourceNotifier, MockTimeSource};
    use super::*;
    use std::{thread, time};

    #[test]
    fn test_batch() {
        let grpc_environment = grpcio::EnvBuilder::new().build();
        let environment = Arc::new(GrpcEnvironment::new(grpc_environment));
        let time_source = Arc::new(MockTimeSource::new());
        let time_notifier = Arc::new(LocalTimeSourceNotifier::new(time_source.clone()));
        let committed = Arc::new(DummyStorageBackend::new());
        let batch = BatchStorageBackend::new(committed.clone(), 1, time_notifier.clone(),environment.clone());

        let key = hash_storage_key(b"value");
        let delay = time::Duration::from_millis(1000);

        time_source.set_mock_time(0, EPOCH_INTERVAL).unwrap();
        time_notifier.notify_subscribers().unwrap();
        thread::sleep(delay);

        assert!(batch.get(key).wait().is_err());
        batch.insert(b"value".to_vec(), 10).wait().unwrap();
        assert_eq!(batch.get(key).wait(), Ok(b"value".to_vec()));
        // Force progression of time.
        time_source.set_mock_time(1, EPOCH_INTERVAL).unwrap();
        time_notifier.notify_subscribers().unwrap();
        thread::sleep(delay);
        // batch.get_key_list();

        // Test that key has not been inserted into committed backend.
        assert!(committed.get(key).wait().is_err());
        // Commit.
        batch.commit().wait().unwrap();
        assert_eq!(committed.get(key).wait(), Ok(b"value".to_vec()));

        // Insert directly to committed and expect the backend to find it.
        let key = hash_storage_key(b"another");
        committed.insert(b"another".to_vec(), 10).wait().unwrap();
        assert_eq!(batch.get(key).wait(), Ok(b"another".to_vec()));
    }
}
