use std::collections::HashMap;
use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;

extern crate clap;
use clap::value_t_or_exit;
extern crate futures;
use futures::future::Future;
use futures::future::Shared;
extern crate grpcio;
use grpcio::ChannelBuilder;
extern crate log;
use log::debug;
use log::trace;
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

pub struct MultilayerBackend {
    /// This map lets us wait on an existing future if we're already bringing an item in from
    /// outside.
    incoming: Arc<Mutex<HashMap<H256, Shared<IncomingFuture>>>>,
    /// Local persistent layer.
    local: Arc<PersistentStorageBackend>,
    /// Last resort layer.
    bottom: Arc<StorageBackend>,
}

impl MultilayerBackend {
    pub fn new(local: Arc<PersistentStorageBackend>, bottom: Arc<StorageBackend>) -> Self {
        Self {
            incoming: Arc::new(Mutex::new(HashMap::new())),
            local,
            bottom,
        }
    }
}

impl StorageBackend for MultilayerBackend {
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        let local = self.local.clone();
        let bottom = self.bottom.clone();
        let incoming = self.incoming.clone();
        // Get the item from local layer.
        self.local
            .get(key)
            .or_else(move |error| {
                trace!(
                    "get: unable to get key {} from local layer: {:?}",
                    key,
                    error
                );
                let incoming_cleanup = incoming.clone();
                let mut incoming_guard = incoming.lock().unwrap();
                incoming_guard
                    .entry(key)
                    .or_insert_with(|| {
                        // Get the item from last resort layer.
                        bottom
                            .get(key)
                            .then(move |result| {
                                match result {
                                    Ok(value) => {
                                        // Save the item to local layer.
                                        futures::future::Either::A(
                                            local.insert(value.clone(), 2).then(move |result| {
                                                // Clear incoming item.
                                                incoming_cleanup.lock().unwrap().remove(&key);
                                                match result {
                                                    Ok(()) => Ok(value),
                                                    Err(error) => Err(Error::new(format!(
                                                        "unable to save item to local layer: {:?}",
                                                        error
                                                    ))),
                                                }
                                            }),
                                        )
                                    }
                                    Err(error) => {
                                        debug!(
                                            "get: unable to get key {} from last resort layer: {:?}",
                                            key, error
                                        );
                                        incoming_cleanup.lock().unwrap().remove(&key);
                                        futures::future::Either::B(futures::future::err(
                                            Error::new("unable to get item from any layer"),
                                        ))
                                    }
                                }
                            })
                            .into_box()
                            .shared()
                    })
                    .clone()
                    .then(clone_shared)
            })
            .into_box()
    }

    fn insert(&self, value: Vec<u8>, expiry: u64) -> BoxFuture<()> {
        self.local
            .insert(value.clone(), expiry)
            .join(self.bottom.insert(value, expiry))
            .and_then(|((), ())| Ok(()))
            .into_box()
    }

    fn get_keys(&self) -> BoxFuture<Arc<Vec<(H256, u64)>>> {
        self.local.get_keys()
    }
}

fn di_factory(
    container: &mut ekiden_di::Container,
) -> ekiden_di::error::Result<Box<std::any::Any>> {
    let env: Arc<Environment> = container.inject()?;
    let args = container.get_arguments().unwrap();
    let local = Arc::new(PersistentStorageBackend::new(Path::new(args.value_of(
        "storage-multilayer-local-storage-base",
    ).unwrap()))
        .map_err(|error| {
        // Can't use chain_error because ekiden_common Error doesn't implement std Error.
        ekiden_di::error::Error::from(format!("Couldn't create local layer: {:?}", error))
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
    let backend: Arc<StorageBackend> = Arc::new(MultilayerBackend::new(local, bottom));
    Ok(Box::new(backend))
}

fn di_arg_local_storage_base<'a, 'b>() -> clap::Arg<'a, 'b> {
    clap::Arg::with_name("storage-multilayer-local-storage-base")
        .long("storage-multilayer-local-storage-base")
        .help("Database path that the local layer of the multilayer storage backend should use")
        .takes_value(true)
        // TODO: default value
        .required(true)
}

fn di_arg_bottom_storage_backend<'a, 'b>() -> clap::Arg<'a, 'b> {
    clap::Arg::with_name("storage-multilayer-bottom-backend")
        .long("storage-multilayer-bottom-backend")
        .help("Last resort layer that the multilayer storage backend should use")
        .takes_value(true)
        .possible_values(&["dynamodb", "remote"])
        .required(true)
        .default_value("remote")
}

fn di_arg_aws_region<'a, 'b>() -> clap::Arg<'a, 'b> {
    clap::Arg::with_name("storage-multilayer-aws-region")
        .long("storage-multilayer-aws-region")
        .help("AWS region that the DynamoDB last resort layer of the multilayer storage backend should use")
        .takes_value(true)
        .required_if("storage-multilayer-storage-backend", "dynamodb")
}

fn di_arg_aws_table_name<'a, 'b>() -> clap::Arg<'a, 'b> {
    clap::Arg::with_name("storage-multilayer-aws-table-name")
        .long("storage-multilayer-aws-table-name")
        .help("Table name that the DynamoDB last resort layer of the multilayer storage backend should use")
        .takes_value(true)
        .required_if("storage-multilayer-storage-backend", "dynamodb")
}

fn di_arg_client_host<'a, 'b>() -> clap::Arg<'a, 'b> {
    clap::Arg::with_name("storage-multilayer-client-host")
        .long("storage-multilayer-client-host")
        .help("Host that the remote last resort layer of the multilayer storage backend should use")
        .takes_value(true)
        .required_if("storage-multilayer-storage-backend", "remote")
        .default_value("127.0.0.1")
}

fn di_arg_client_port<'a, 'b>() -> clap::Arg<'a, 'b> {
    clap::Arg::with_name("storage-multilayer-client-port")
        .long("storage-multilayer-client-port")
        .help("Port that the remote last resort layer of the multilayer storage backend should use")
        .takes_value(true)
        .required_if("storage-multilayer-storage-backend", "remote")
        .default_value("42261")
}

// Register for dependency injection. When using DynamoDB as the last resort layer, the factory
// starts a thread for the reactor core that runs forever.
create_component!(
    multilayer,
    "storage-backend",
    MultilayerBackend,
    StorageBackend,
    di_factory,
    [
        di_arg_local_storage_base(),
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
    use ekiden_common::futures::Future;
    use ekiden_storage_base;
    use ekiden_storage_base::StorageBackend;
    extern crate ekiden_storage_dummy;
    use self::ekiden_storage_dummy::DummyStorageBackend;
    use ekiden_storage_persistent::PersistentStorageBackend;

    use MultilayerBackend;
    #[test]
    fn play() {
        ekiden_common::testing::try_init_logging();

        let local = Arc::new(
            PersistentStorageBackend::new(Path::new("/tmp/ekiden-test-storage-persistent/"))
                .unwrap(),
        );
        let bottom = Arc::new(DummyStorageBackend::new());
        let storage = MultilayerBackend::new(local.clone(), bottom.clone());

        // Test retrieving item from local layer.
        let reference_value_local = b"hello from local".to_vec();
        let reference_key_local = ekiden_storage_base::hash_storage_key(&reference_value_local);
        local
            .insert(reference_value_local.clone(), 55)
            .wait()
            .unwrap();
        let retrieve_value_local = storage.get(reference_key_local).wait().unwrap();
        assert_eq!(retrieve_value_local, reference_value_local);

        // Test retrieving item from last resort layer.
        let reference_value_bottom = b"hello from aws".to_vec();
        let reference_key_bottom = ekiden_storage_base::hash_storage_key(&reference_value_bottom);
        bottom
            .insert(reference_value_bottom.clone(), 55)
            .wait()
            .unwrap();
        let retrieve_value_bottom = storage.get(reference_key_bottom).wait().unwrap();
        assert_eq!(retrieve_value_bottom, reference_value_bottom);

        // Test round trip insert and get.
        let reference_value = b"hello from multilayer".to_vec();
        let reference_key = ekiden_storage_base::hash_storage_key(&reference_value);
        storage.insert(reference_value.clone(), 55).wait().unwrap();
        let roundtrip_value = storage.get(reference_key).wait().unwrap();
        assert_eq!(roundtrip_value, reference_value);

        // Test presence in local layer.
        let persisted_value_local = local.get(reference_key).wait().unwrap();
        assert_eq!(persisted_value_local, reference_value);

        // Test presence in last resort layer.
        let persisted_value_bottom = bottom.get(reference_key).wait().unwrap();
        assert_eq!(persisted_value_bottom, reference_value);
    }
}
