use std::convert::Into;
use std::sync::Arc;

use ekiden_common::bytes::B256;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, BoxFuture, Future, Stream};
use ekiden_scheduler_api as api;
use grpcio::RpcStatusCode::{Internal, InvalidArgument};
use grpcio::{RpcContext, ServerStreamingSink, UnarySink, WriteFlags};
use protobuf::RepeatedField;

use super::backend::{Committee, Scheduler};

#[derive(Clone)]
pub struct SchedulerService {
    inner: Arc<Scheduler>,
}

impl SchedulerService {
    pub fn new(backend: Arc<Scheduler>) -> Self {
        Self { inner: backend }
    }
}

impl api::Scheduler for SchedulerService {
    fn get_committees(
        &self,
        ctx: RpcContext,
        req: api::CommitteeRequest,
        sink: UnarySink<api::CommitteeResponse>,
    ) {
        let f = move || -> Result<BoxFuture<Vec<Committee>>, Error> {
            let contract_id = B256::from_slice(req.get_contract_id());
            Ok(self.inner.get_committees(contract_id))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(committees) => {
                    let mut resp = api::CommitteeResponse::new();
                    let mut members = Vec::new();
                    for member in committees.iter() {
                        members.push(member.to_owned().into());
                    }
                    resp.set_committee(RepeatedField::from_vec(members));
                    Ok(resp)
                }
                Err(e) => Err(e),
            }),
            Err(e) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, e).map_err(|_e| ()));
                return;
            }
        };
        ctx.spawn(f.then(move |r| match r {
            Ok(ret) => sink.success(ret),
            Err(e) => invalid_rpc!(sink, Internal, e),
        }).map_err(|_e| ()));
    }

    fn watch_committees(
        &self,
        ctx: RpcContext,
        _req: api::WatchRequest,
        sink: ServerStreamingSink<api::WatchResponse>,
    ) {
        let f = self.inner
            .watch_committees()
            .map(|res| -> (api::WatchResponse, WriteFlags) {
                let mut r = api::WatchResponse::new();
                r.set_committee(res.into());
                (r, WriteFlags::default())
            });
        ctx.spawn(f.forward(sink).then(|_f| future::ok(())));
    }
}
