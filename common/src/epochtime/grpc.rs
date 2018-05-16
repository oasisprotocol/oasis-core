//! Epoch time service - gRPC service for a TimeSource implementation.
use std::error::Error as StdError;
use std::sync::Arc;

use grpcio::{Channel, Environment, RpcContext, RpcStatus, ServerStreamingSink, UnarySink,
             WriteFlags};
use grpcio::RpcStatusCode::InvalidArgument;

use super::{EpochTime, TimeSource, TimeSourceNotifier};
use super::local::LocalTimeSourceNotifier;
use super::super::error::Error;
use futures::{future, stream, BoxFuture, BoxStream, Future, Stream};
use node::Node;

use ekiden_common_api as api;

pub struct EpochTimeService {
    inner: Arc<TimeSource>,
    notifier: LocalTimeSourceNotifier,
}

impl EpochTimeService {
    pub fn new(backend: Arc<TimeSource>) -> Self {
        Self {
            inner: backend.clone(),
            notifier: LocalTimeSourceNotifier::new(backend.clone()),
        }
    }
}

macro_rules! invalid {
    ($sink:ident,$code:ident,$e:expr) => {
        $sink.fail(RpcStatus::new(
            $code,
            Some($e.description().to_owned()),
        ))
    }
}

impl api::TimeSource for EpochTimeService {
    fn get_epoch(
        &self,
        ctx: RpcContext,
        _req: api::EpochRequest,
        sink: UnarySink<api::EpochResponse>,
    ) {
        let resp = match self.inner.get_epoch() {
            Ok(r) => r,
            Err(e) => {
                ctx.spawn(invalid!(sink, InvalidArgument, e).map_err(|_e| ()));
                return;
            }
        };
        ctx.spawn(
            future::lazy(move || {
                let mut ret = api::EpochResponse::new();
                ret.set_current_epoch(resp.0);
                ret.set_within_epoch(resp.1);
                sink.success(ret)
            }).map_err(|_e| ()),
        );
    }

    fn watch_epochs(
        &self,
        ctx: RpcContext,
        _req: api::WatchEpochRequest,
        sink: ServerStreamingSink<api::WatchEpochResponse>,
    ) {
        let f = self.notifier
            .watch_epochs()
            .map(|res| -> (api::WatchEpochResponse, WriteFlags) {
                let mut r = api::WatchEpochResponse::new();
                r.set_current_epoch(res);
                (r, WriteFlags::default())
            });
        ctx.spawn(f.forward(sink).then(|_f| future::ok(())));
    }
}

/// Time Source client implements the time interfaces based on a remote time service.
pub struct TimeSourceClient(api::TimeSourceClient);

impl TimeSourceClient {
    pub fn new(channel: Channel) -> Self {
        TimeSourceClient(api::TimeSourceClient::new(channel))
    }

    pub fn from_node(node: Node, env: Arc<Environment>) -> Self {
        TimeSourceClient::new(node.connect(env))
    }
}

impl TimeSourceNotifier for TimeSourceClient {
    fn get_epoch(&self) -> BoxFuture<EpochTime> {
        let req = api::EpochRequest::new();

        match self.0.get_epoch_async(&req) {
            Ok(f) => Box::new(f.then(|result| match result {
                Ok(r) => Ok(r.get_current_epoch()),
                Err(e) => Err(Error::new(e.description())),
            })),
            Err(e) => Box::new(future::err(Error::new(e.description()))),
        }
    }

    fn watch_epochs(&self) -> BoxStream<EpochTime> {
        let req = api::WatchEpochRequest::new();

        match self.0.watch_epochs(&req) {
            Ok(s) => Box::new(s.then(|result| match result {
                Ok(r) => Ok(r.get_current_epoch()),
                Err(e) => Err(Error::new(e.description())),
            })),
            Err(e) => Box::new(stream::once::<EpochTime, _>(Err(Error::new(
                e.description(),
            )))),
        }
    }
}
