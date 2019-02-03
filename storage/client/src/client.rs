//! Storage gRPC client.
use grpcio::{CallOption, Channel};
use rustracing::tag;

use ekiden_common::{
    bytes::H256,
    error::Error,
    futures::{prelude::*, IntoFuture},
};
use ekiden_storage_base::{InsertOptions, StorageBackend};
use ekiden_tracing::{self, inject_to_options};

mod api {
    pub use crate::generated::{storage::*, storage_grpc::*};
}

/// Storage client implements the storage interface.  It exposes storage calls across a gRPC channel.
pub struct StorageClient(api::StorageClient);

impl StorageClient {
    pub fn new(channel: Channel) -> Self {
        StorageClient(api::StorageClient::new(channel))
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

    fn get_batch(&self, keys: Vec<H256>) -> BoxFuture<Vec<Option<Vec<u8>>>> {
        let mut req = api::GetBatchRequest::new();
        req.set_ids(keys.iter().map(|k| k.to_vec()).collect());
        match self.0.get_batch_async(&req) {
            Ok(f) => Box::new(
                f.map(|mut resp| -> Vec<Option<Vec<u8>>> {
                    let mut data = resp.take_data().to_vec();
                    let items = data
                        .drain(..)
                        .map(|item| if item.is_empty() { None } else { Some(item) })
                        .collect();
                    items
                })
                .map_err(|error| Error::new(format!("{:?}", error))),
            ),
            Err(error) => Box::new(future::err(Error::new(format!("{:?}", error)))),
        }
    }

    fn insert(&self, value: Vec<u8>, expiry: u64, _opts: InsertOptions) -> BoxFuture<()> {
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
                })
                .map(|_r| ())
                .map_err(|error| Error::new(format!("{:?}", error))),
            ),
            Err(error) => Box::new(future::err(Error::new(format!("{:?}", error)))),
        }
    }

    fn insert_batch(&self, values: Vec<(Vec<u8>, u64)>, _opts: InsertOptions) -> BoxFuture<()> {
        let mut req = api::InsertBatchRequest::new();
        for (value, expiry) in values {
            let mut item = api::InsertRequest::new();
            item.set_data(value);
            item.set_expiry(expiry);
            req.items.push(item);
        }

        // TODO: correlate with whatever initiates this
        let span = ekiden_tracing::get_tracer()
            .span("storage-client-insert-batch")
            .tag(tag::StdTag::span_kind("client"))
            .start();
        let options = inject_to_options(CallOption::default(), span.context());

        match self.0.insert_batch_async_opt(&req, options) {
            Ok(f) => Box::new(
                f.then(|result| {
                    drop(span);
                    result
                })
                .map(|_r| ())
                .map_err(|error| Error::new(format!("{:?}", error))),
            ),
            Err(error) => Box::new(future::err(Error::new(format!("{:?}", error)))),
        }
    }

    fn get_keys(&self) -> BoxStream<(H256, u64)> {
        let req = api::GetKeysRequest::new();
        self.0
            .get_keys(&req)
            .map(|rx| rx.map(|message| (message.get_key().into(), message.get_expiry())))
            .into_future()
            .flatten_stream()
            .map_err(|error| error.into())
            .into_box()
    }
}
