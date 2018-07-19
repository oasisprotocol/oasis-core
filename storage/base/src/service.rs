use std::sync::Arc;

use ekiden_common::futures::{BoxFuture, Future};
use ekiden_storage_api as api;
use grpcio::RpcStatusCode::{Internal, InvalidArgument};
use grpcio::{RpcContext, UnarySink};
use protobuf::RepeatedField;

use super::backend::StorageBackend;
use ekiden_common::bytes::H256;
use ekiden_common::error::Error;

#[derive(Clone)]
pub struct StorageService {
    inner: Arc<StorageBackend>,
}

impl StorageService {
    pub fn new(backend: Arc<StorageBackend>) -> Self {
        Self { inner: backend }
    }
}

impl api::Storage for StorageService {
    fn get(&self, ctx: RpcContext, req: api::GetRequest, sink: UnarySink<api::GetResponse>) {
        let f = move || -> Result<BoxFuture<Vec<u8>>, Error> {
            let k = H256::from(req.get_id().clone());
            Ok(self.inner.get(k))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(data) => {
                    let mut response = api::GetResponse::new();
                    response.set_data(data);
                    Ok(response)
                }
                Err(e) => Err(e),
            }),
            Err(e) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, e).map_err(|_e| ()));
                return;
            }
        };
        ctx.spawn(
            f.then(move |r| match r {
                Ok(ret) => sink.success(ret),
                Err(e) => invalid_rpc!(sink, Internal, e),
            }).map_err(|_e| ()),
        );
    }

    fn insert(
        &self,
        ctx: RpcContext,
        req: api::InsertRequest,
        sink: UnarySink<api::InsertResponse>,
    ) {
        let f = move || -> Result<BoxFuture<()>, Error> {
            Ok(self.inner.insert(req.get_data().to_vec(), req.get_expiry()))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(()) => Ok(api::InsertResponse::new()),
                Err(e) => Err(e),
            }),
            Err(e) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, e).map_err(|_e| ()));
                return;
            }
        };
        ctx.spawn(
            f.then(move |r| match r {
                Ok(ret) => sink.success(ret),
                Err(error) => {
                    error!("Failed to insert data to storage backend: {:?}", error);
                    invalid_rpc!(sink, Internal, error)
                }
            }).map_err(|_e| ()),
        );
    }

    fn get_keys(
        &self,
        ctx: RpcContext,
        _req: api::GetKeysRequest,
        sink: UnarySink<api::GetKeysResponse>,
    ) {
        let f = move || -> Result<BoxFuture<Arc<Vec<(H256, u64)>>>, Error> {
            Ok(self.inner.get_keys())
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(items) => {
                    let mut resp = api::GetKeysResponse::new();
                    let mut keys = Vec::new();
                    let mut expiry = Vec::new();
                    for item in items.iter() {
                        keys.push(item.0.to_vec());
                        expiry.push(item.1);
                    }
                    resp.set_keys(RepeatedField::from_vec(keys));
                    resp.set_expiry(expiry);
                    Ok(resp)
                }
                Err(e) => Err(e),
            }),
            Err(e) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, e).map_err(|_e| ()));
                return;
            }
        };
        ctx.spawn(
            f.then(move |r| match r {
                Ok(ret) => sink.success(ret),
                Err(error) => {
                    error!("Failed to insert data to storage backend: {:?}", error);
                    invalid_rpc!(sink, Internal, error)
                }
            }).map_err(|_e| ()),
        );
    }
}
