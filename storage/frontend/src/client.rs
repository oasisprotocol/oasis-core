//! Storage gRPC client.
use std::sync::Arc;

use grpcio::{CallOption, Channel, ChannelBuilder};
use rustracing::tag;

use ekiden_common::bytes::H256;
use ekiden_common::environment::Environment;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, BoxFuture, Future};
use ekiden_common::identity::NodeIdentity;
use ekiden_common::node::Node;
use ekiden_storage_api as api;
use ekiden_storage_base::StorageBackend;
use ekiden_tracing::{self, inject_to_options};

/// Storage client implements the storage interface.  It exposes storage calls across a gRPC channel.
pub struct StorageClient(api::StorageClient);

impl StorageClient {
    pub fn new(channel: Channel) -> Self {
        StorageClient(api::StorageClient::new(channel))
    }

    pub fn from_node(
        node: &Node,
        environment: Arc<Environment>,
        identity: Arc<NodeIdentity>,
    ) -> Self {
        StorageClient::new(node.connect(environment, identity))
    }
}

impl StorageBackend for StorageClient {
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        let mut req = api::GetRequest::new();
        req.set_id(key.to_vec());
        match self.0.get_async(&req) {
            Ok(f) => Box::new(
                f.map(|mut resp| -> Vec<u8> { resp.take_data() })
                    .map_err(|error| Error::new(format!("{:?}", error))),
            ),
            Err(error) => Box::new(future::err(Error::new(format!("{:?}", error)))),
        }
    }

    fn insert(&self, value: Vec<u8>, expiry: u64) -> BoxFuture<()> {
        let mut req = api::InsertRequest::new();
        req.set_data(value);
        req.set_expiry(expiry);

        // TODO: correlate with whatever initiates this
        let span = ekiden_tracing::get_tracer()
            .span("storage-client-insert")
            .tag(tag::StdTag::span_kind("client"))
            .start();
        let options = inject_to_options(CallOption::default(), span.context());

        match self.0.insert_async_opt(&req, options) {
            Ok(f) => Box::new(
                f.then(|result| {
                    drop(span);
                    result
                }).map(|_r| ())
                    .map_err(|error| Error::new(format!("{:?}", error))),
            ),
            Err(error) => Box::new(future::err(Error::new(format!("{:?}", error)))),
        }
    }

    fn get_keys(&self) -> BoxFuture<Arc<Vec<(H256, u64)>>> {
        let req = api::GetKeysRequest::new();
        match self.0.get_keys_async(&req) {
            Ok(f) => Box::new(f.map(|resp| -> Arc<Vec<(H256, u64)>> {
                let mut items = Vec::new();
                for item in (*resp.get_keys()).iter().zip(resp.get_expiry()) {
                    items.push((H256::from(item.0.as_slice()), *item.1));
                }
                Arc::new(items)
            }).map_err(|error| Error::new(format!("{:?}", error)))),
            Err(error) => Box::new(future::err(Error::new(format!("{:?}", error)))),
        }
    }
}

// Register for dependency injection.
create_component!(
    remote,
    "storage-backend",
    StorageClient,
    StorageBackend,
    (|container: &mut Container| -> Result<Box<Any>> {
        let environment: Arc<Environment> = container.inject()?;

        let args = container.get_arguments().unwrap();
        let channel = ChannelBuilder::new(environment.grpc())
            .max_receive_message_len(i32::max_value())
            .max_send_message_len(i32::max_value())
            .connect(&format!(
                "{}:{}",
                args.value_of("storage-client-host").unwrap(),
                args.value_of("storage-client-port").unwrap(),
            ));

        let instance: Arc<StorageBackend> = Arc::new(StorageClient::new(channel));
        Ok(Box::new(instance))
    }),
    [
        Arg::with_name("storage-client-host")
            .long("storage-client-host")
            .help("(remote storage backend) Host that the storage client should connect to")
            .takes_value(true)
            .default_value("127.0.0.1"),
        Arg::with_name("storage-client-port")
            .long("storage-client-port")
            .help("(remote storage backend) Port that the storage client should connect to")
            .takes_value(true)
            .default_value("42261")
    ]
);
