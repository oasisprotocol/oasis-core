#![feature(use_extern_macros)]

use std::collections::BTreeMap;
use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;

extern crate clap;
use clap::value_t_or_exit;
extern crate futures;
use futures::future::Future;
use futures::future::Shared;
use futures::stream::Stream;
extern crate grpcio;
use grpcio::ChannelBuilder;
extern crate log;
use log::log;
use log::trace;
use log::warn;
extern crate rusoto_core;
extern crate tokio_core;

extern crate ekiden_common;
use ekiden_common::bytes::H256;
use ekiden_common::environment::Environment;
use ekiden_common::error::Error;
use ekiden_common::futures::BoxFuture;
use ekiden_common::futures::FutureExt;
extern crate ekiden_di;
use ekiden_di::create_component;
extern crate ekiden_epochtime;
extern crate ekiden_storage_base;
use ekiden_storage_base::BatchStorage;
use ekiden_storage_base::StorageBackend;
extern crate ekiden_storage_dynamodb;
use ekiden_storage_dynamodb::DynamoDbBackend;
extern crate ekiden_storage_frontend;
use ekiden_storage_frontend::StorageClient;
extern crate ekiden_storage_persistent;
use ekiden_storage_persistent::PersistentStorageBackend;

type IncomingFuture = BoxFuture<Vec<u8>>;

fn clone_shared<I, E>(
    r: Result<futures::future::SharedItem<I>, futures::future::SharedError<E>>,
) -> Result<I, E>
where
    I: Clone,
    E: Clone,
{
    match r {
        Ok(i) => Ok(i.deref().clone()),
        Err(e) => Err(e.deref().clone()),
    }
}

/// Special instructions to override lookup from the sled layer.
enum AccessedItem {
    /// We're already trying to access this item. Provides a shared future that you can use to wait
    /// on that.
    Incoming(Shared<IncomingFuture>),
    /// We recently added the item, and we're working on writing it.
    Writeback(Vec<u8>),
}

struct WaitSet {
    error_tx: futures::sync::mpsc::UnboundedSender<Error>,
    error_rx: futures::sync::mpsc::UnboundedReceiver<Error>,
}

pub struct MultilayerBackend {
    /// We do some writeback operations on the shared executor.
    env: Arc<Environment>,
    /// This map lets us look up whether we're already accessing an item.
    accessed: Arc<Mutex<BTreeMap<H256, AccessedItem>>>,
    /// The bookkeeping for batches.
    batch: RwLock<Option<WaitSet>>,

    // Backing layers, as specified in RFC 0004.
    sled: Arc<PersistentStorageBackend>,
    // TODO: remote_sled: Arc<...>,
    bottom: Arc<StorageBackend>,
}

impl MultilayerBackend {
    pub fn new(
        env: Arc<Environment>,
        sled: Arc<PersistentStorageBackend>,
        // TODO: remote_sled: Arc<...>,
        bottom: Arc<StorageBackend>,
    ) -> Self {
        Self {
            env,
            accessed: Arc::new(Mutex::new(BTreeMap::new())),
            batch: RwLock::new(None),
            sled,
            // remote_sled,
            bottom,
        }
    }
}

impl StorageBackend for MultilayerBackend {
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        let mut accessed_guard = self.accessed.lock().unwrap();
        match accessed_guard.get(&key) {
            Some(&AccessedItem::Incoming(ref f)) => {
                return Box::new(f.clone().then(clone_shared));
            }
            Some(&AccessedItem::Writeback(ref v)) => {
                return Box::new(futures::future::ok(v.clone()));
            }
            None => {}
        }

        let sled = self.sled.clone();
        // TODO: let remote_sled = self.remote_sled.clone();
        let bottom = self.bottom.clone();
        let accessed = self.accessed.clone();
        let env = self.env.clone();
        // Get the item from sled.
        let f = self.sled
            .get(key)
            .or_else(move |e| {
                trace!("get: unable to get key {} from sled layer: {:?}", key, e);
                // Get the item from remote sled.
                // TODO: remote_sled.get(key)
                futures::future::err(Error::new("remote sled layer not implemented"))
                    .or_else(move |e| {
                        trace!(
                            "get: unable to get key {} from remote sled layer: {:?}",
                            key,
                            e
                        );
                        // Get the item from last resort.
                        // If there's a thundering herd, God help us.
                        bottom.get(key)
                    })
                    .then(move |r| {
                        match r {
                            Ok(v) => {
                                // Set accessed item to writeback.
                                accessed
                                    .lock()
                                    .unwrap()
                                    .insert(key, AccessedItem::Writeback(v.clone()));
                                // Start async writeback.
                                env.spawn(Box::new(sled.insert(v.clone(), 2).then(move |r| {
                                    if let Err(e) = r {
                                        warn!(
                                            "get: unable to persist key {} to sled layer: {:?}",
                                            key, e
                                        );
                                    }
                                    // Clear writeback accessed item.
                                    accessed.lock().unwrap().remove(&key);
                                    Ok(())
                                })));
                                Ok(v)
                            }
                            Err(e) => {
                                trace!(
                                    "get: unable to get key {} from last resort layer: {:?}",
                                    key,
                                    e
                                );
                                // Clear incoming accessed item.
                                accessed.lock().unwrap().remove(&key);
                                Err(Error::new("unable to get from any layer"))
                            }
                        }
                    })
            })
            .into_box()
            .shared();
        accessed_guard.insert(key, AccessedItem::Incoming(f.clone()));
        Box::new(f.then(clone_shared))
    }

    fn insert(&self, value: Vec<u8>, expiry: u64) -> BoxFuture<()> {
        let key = ekiden_storage_base::hash_storage_key(&value);
        // Set accessed item to writeback.
        let mut accessed_guard = self.accessed.lock().unwrap();
        match accessed_guard.get(&key) {
            Some(&AccessedItem::Incoming(_)) => {
                trace!(
                    "insert: tried to insert key {} which is already Incoming. ignoring",
                    key
                );
                return Box::new(futures::future::ok(()));
            }
            Some(&AccessedItem::Writeback(_)) => {
                trace!(
                    "insert: tried to insert key {} which is already Writeback. ignoring",
                    key
                );
                return Box::new(futures::future::ok(()));
            }
            None => {}
        }
        accessed_guard.insert(key, AccessedItem::Writeback(value.clone()));
        let accessed = self.accessed.clone();
        let error_tx = self.batch
            .read()
            .unwrap()
            .as_ref()
            .map(|batch| batch.error_tx.clone());
        self.env
            .spawn(Box::new(self.sled.insert(value.clone(), expiry).then(
                move |r| {
                    if let Err(e) = r {
                        warn!(
                            "insert: unable to persist key {} to sled layer: {:?}",
                            key, e
                        );
                    }
                    // Clear writeback accessed item.
                    accessed.lock().unwrap().remove(&key);
                    Ok(())
                },
            )));
        self.env
            .spawn(Box::new(self.bottom.insert(value, expiry).then(move |r| {
                if let Err(e) = r {
                    warn!(
                        "insert: unable to back up key {} to last resort layer: {:?}",
                        key, e
                    );
                    if let Some(tx) = error_tx {
                        drop(tx.unbounded_send(e));
                    }
                }
                Ok(())
            })));
        Box::new(futures::future::ok(()))
    }

    fn get_keys(&self) -> BoxFuture<Arc<Vec<(H256, u64)>>> {
        self.sled.get_keys()
    }
}

impl BatchStorage for MultilayerBackend {
    fn start_batch(&self) {
        let mut guard = self.batch.write().unwrap();
        assert!(guard.is_none());
        let (error_tx, error_rx) = futures::sync::mpsc::unbounded();
        *guard = Some(WaitSet { error_tx, error_rx });
    }

    fn end_batch(&self) -> BoxFuture<()> {
        self.batch
            .write()
            .unwrap()
            .take()
            .unwrap()
            .error_rx
            .collect()
            .then(|r| {
                let errors = r.unwrap();
                if errors.is_empty() {
                    Ok(())
                } else {
                    Err(Error::new(format!("Some inserts failed: {:?}", errors)))
                }
            })
            .into_box()
    }

    fn persistent_storage(&self) -> Arc<StorageBackend> {
        self.sled.clone()
    }
}

fn di_factory(
    container: &mut ekiden_di::Container,
) -> ekiden_di::error::Result<Box<std::any::Any>> {
    let env: Arc<Environment> = container.inject()?;
    let args = container.get_arguments().unwrap();
    let sled = Arc::new(PersistentStorageBackend::new(Path::new(args.value_of(
        "storage-multilayer-sled-storage-base",
    ).unwrap()))
        .map_err(|e| {
        // Can't use chain_error because ekiden_common Error doesn't implement std Error.
        ekiden_di::error::Error::from(format!("Couldn't create sled layer: {:?}", e))
    })?);
    let bottom: Arc<StorageBackend> =
        match args.value_of("storage-multilayer-bottom-backend").unwrap() {
            "dynamodb" => {
                let aws_region = value_t_or_exit!(
                    args,
                    "storage-multilayer-aws-region",
                    rusoto_core::region::Region
                );
                let aws_table_name = args.value_of("storage-multilayer-aws-table-name")
                    .unwrap()
                    .to_string();
                let (init_tx, init_rx) = futures::sync::oneshot::channel();
                std::thread::spawn(|| match tokio_core::reactor::Core::new() {
                    Ok(mut core) => {
                        init_tx.send(Ok(core.remote())).unwrap();
                        loop {
                            core.turn(None);
                        }
                    }
                    Err(e) => {
                        init_tx.send(Err(e)).unwrap();
                    }
                });
                use ekiden_di::error::ResultExt;
                let remote = init_rx
                    .wait()
                    .unwrap()
                    .chain_err(|| "Couldn't create rector core")?;
                Arc::new(DynamoDbBackend::new(remote, aws_region, aws_table_name))
            }
            "remote" => {
                let channel = ChannelBuilder::new(env.grpc())
                    .max_receive_message_len(i32::max_value())
                    .max_send_message_len(i32::max_value())
                    .connect(&format!(
                        "{}:{}",
                        args.value_of("storage-multilayer-client-host").unwrap(),
                        args.value_of("storage-multilayer-client-port").unwrap(),
                    ));
                Arc::new(StorageClient::new(channel))
            }
            bottom_type => panic!("no match branch for last resort layer {}", bottom_type),
        };
    let backend: Arc<BatchStorage> = Arc::new(MultilayerBackend::new(env, sled, bottom));
    Ok(Box::new(backend))
}

fn di_arg_sled_storage_base<'a, 'b>() -> clap::Arg<'a, 'b> {
    clap::Arg::with_name("storage-multilayer-sled-storage-base")
        .long("storage-multilayer-sled-storage-base")
        .help("Database path that the sled layer of the RFC 0004 multilayer storage backend should use")
        .takes_value(true)
        // TODO: default value
        .required(true)
}

fn di_arg_bottom_storage_backend<'a, 'b>() -> clap::Arg<'a, 'b> {
    clap::Arg::with_name("storage-multilayer-bottom-backend")
        .long("storage-multilayer-bottom-backend")
        .help("Last resort layer that the RFC 0004 multilayer storage backend should use")
        .takes_value(true)
        .possible_values(&["dynamodb", "remote"])
        .required(true)
        .default_value("remote")
}

fn di_arg_aws_region<'a, 'b>() -> clap::Arg<'a, 'b> {
    clap::Arg::with_name("storage-multilayer-aws-region")
        .long("storage-multilayer-aws-region")
        .help("AWS region that the AWS layer of the RFC 0004 multilayer storage backend should use")
        .takes_value(true)
        .required_if("storage-multilayer-storage-backend", "dynamodb")
}

fn di_arg_aws_table_name<'a, 'b>() -> clap::Arg<'a, 'b> {
    clap::Arg::with_name("storage-multilayer-aws-table-name")
        .long("storage-multilayer-aws-table-name")
        .help("DynamoDB table that the AWS layer of the RFC 0004 multilayer storage backend should use")
        .takes_value(true)
        .required_if("storage-multilayer-storage-backend", "dynamodb")
}

fn di_arg_client_host<'a, 'b>() -> clap::Arg<'a, 'b> {
    clap::Arg::with_name("storage-multilayer-client-host")
        .long("storage-multilayer-client-host")
        .help("Host that the RFC 0004 multilayer storage backend should use")
        .takes_value(true)
        .required_if("storage-multilayer-storage-backend", "remote")
        .default_value("127.0.0.1")
}

fn di_arg_client_port<'a, 'b>() -> clap::Arg<'a, 'b> {
    clap::Arg::with_name("storage-multilayer-client-port")
        .long("storage-multilayer-client-port")
        .help("Port that the RFC 0004 multilayer storage backend should use")
        .takes_value(true)
        .required_if("storage-multilayer-storage-backend", "remote")
        .default_value("42261")
}

// Register for dependency injection. This preparation starts a thread for the reactor core that
// runs forever.
create_component!(
    multilayer,
    "batch-storage",
    MultilayerBackend,
    BatchStorage,
    di_factory,
    [
        di_arg_sled_storage_base(),
        di_arg_bottom_storage_backend(),
        di_arg_aws_region(),
        di_arg_aws_table_name(),
        di_arg_client_host(),
        di_arg_client_port()
    ]
);

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use ekiden_common;
    use ekiden_common::environment::GrpcEnvironment;
    use ekiden_storage_base;
    use ekiden_storage_base::BatchStorage;
    use ekiden_storage_base::StorageBackend;
    use ekiden_storage_dynamodb::DynamoDbBackend;
    use ekiden_storage_persistent::PersistentStorageBackend;
    use grpcio;
    use log::log;
    use log::warn;
    use rusoto_core;
    use rusoto_core::ProvideAwsCredentials;
    use tokio_core;

    use MultilayerBackend;
    #[test]
    fn play() {
        ekiden_common::testing::try_init_logging();
        let mut core = tokio_core::reactor::Core::new().unwrap();
        let grpc_environment = grpcio::EnvBuilder::new().build();
        let environment = Arc::new(GrpcEnvironment::new(grpc_environment));

        if let Err(e) = core.run(rusoto_core::reactor::CredentialsProvider::default().credentials())
        {
            // Skip this if AWS credentials aren't available.
            warn!("{} Skipping multilayer storage test.", e);
            return;
        }

        let sled = Arc::new(
            PersistentStorageBackend::new(Path::new("/tmp/ekiden-test-storage-persistent/"))
                .unwrap(),
        );
        let aws = Arc::new(DynamoDbBackend::new(
            core.remote(),
            "us-west-2".parse().unwrap(),
            "test".to_string(),
        ));
        let storage = MultilayerBackend::new(environment, sled.clone(), aws.clone());

        // Test retrieving item from sled layer.
        let reference_value_sled = b"hello from sled".to_vec();
        let reference_key_sled = ekiden_storage_base::hash_storage_key(&reference_value_sled);
        core.run(sled.insert(reference_value_sled.clone(), 55))
            .unwrap();
        let retrieve_value_sled = core.run(storage.get(reference_key_sled)).unwrap();
        assert_eq!(retrieve_value_sled, reference_value_sled);

        // Test retrieving item from AWS layer.
        let reference_value_aws = b"hello from aws".to_vec();
        let reference_key_aws = ekiden_storage_base::hash_storage_key(&reference_value_aws);
        core.run(aws.insert(reference_value_aws.clone(), 55))
            .unwrap();
        let retrieve_value_aws = core.run(storage.get(reference_key_aws)).unwrap();
        assert_eq!(retrieve_value_aws, reference_value_aws);

        // Test round trip insert and get.
        let reference_value = b"hello from RFC 0004".to_vec();
        let reference_key = ekiden_storage_base::hash_storage_key(&reference_value);
        core.run(storage.insert(reference_value.clone(), 55))
            .unwrap();
        let roundtrip_value = core.run(storage.get(reference_key)).unwrap();
        assert_eq!(roundtrip_value, reference_value);

        // Test flush.
        let reference_value = b"see you online".to_vec();
        // key base64 should be yv+yNRRnh0p9iWCkKmziz4x7FhqbryDe5egHXcF6/Os=
        let reference_key = ekiden_storage_base::hash_storage_key(&reference_value);
        storage.start_batch();
        core.run(storage.insert(reference_value.clone(), 55))
            .unwrap();
        core.run(storage.end_batch()).unwrap();
        let persisted_value = core.run(aws.get(reference_key)).unwrap();
        assert_eq!(persisted_value, reference_value);
    }
}
