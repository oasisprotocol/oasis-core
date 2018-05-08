//! Storage gRPC client.
use std::error::Error as StdError;
use std::sync::Arc;

use grpcio::{Channel, Environment};

use ekiden_common::bytes::H256;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, BoxFuture, Future};
use ekiden_common::node::Node;
use ekiden_storage_api as api;
use ekiden_storage_base::StorageBackend;

/// Storage client implements the storage interface.  It exposes storage calls across a gRPC channel.
pub struct StorageClient(api::StorageClient);

impl StorageClient {
    pub fn new(channel: Channel) -> Self {
        StorageClient(api::StorageClient::new(channel))
    }

    pub fn from_node(node: Node, env: Arc<Environment>) -> Self {
        StorageClient::new(node.connect(env))
    }
}

impl StorageBackend for StorageClient {
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        let mut req = api::GetRequest::new();
        req.set_id(key.to_vec());
        match self.0.get_async(&req) {
            Ok(f) => Box::new(
                f.map(|mut resp| -> Vec<u8> { resp.take_data() })
                    .map_err(|e| Error::new(e.description())),
            ),
            Err(e) => Box::new(future::err(Error::new(e.description()))),
        }
    }

    fn insert(&self, value: Vec<u8>, expiry: u64) -> BoxFuture<()> {
        let mut req = api::InsertRequest::new();
        req.set_data(value);
        req.set_expiry(expiry);

        match self.0.insert_async(&req) {
            Ok(f) => Box::new(f.map(|_r| ()).map_err(|e| Error::new(e.description()))),
            Err(e) => Box::new(future::err(Error::new(e.description()))),
        }
    }
}
