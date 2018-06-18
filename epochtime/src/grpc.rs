//! Epoch time service - gRPC service for a TimeSource implementation.
use std::error::Error as StdError;
use std::sync::Arc;

use grpcio::RpcStatusCode::InvalidArgument;
use grpcio::{self, Channel, ChannelBuilder, RpcContext, RpcStatus, ServerStreamingSink, UnarySink,
             WriteFlags};

use super::interface::{EpochTime, TimeSource, TimeSourceNotifier};
use super::local::LocalTimeSourceNotifier;
use ekiden_common::environment::Environment;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, stream, BoxFuture, BoxStream, Future, Stream};
use ekiden_common::node::Node;

use ekiden_common_api as api;

#[derive(Clone)]
pub struct EpochTimeService {
    inner: Arc<TimeSource>,
    notifier: Arc<LocalTimeSourceNotifier>,
}

impl EpochTimeService {
    pub fn new(backend: Arc<TimeSource>) -> Self {
        Self {
            inner: backend.clone(),
            notifier: Arc::new(LocalTimeSourceNotifier::new(backend.clone())),
        }
    }
}

macro_rules! invalid {
    ($sink:ident, $code:ident, $e:expr) => {
        $sink.fail(RpcStatus::new($code, Some($e.description().to_owned())))
    };
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

    pub fn from_node(node: Node, env: Arc<grpcio::Environment>) -> Self {
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

// Register for dependency injection.
create_component!(
    remote,
    "time-source",
    TimeSourceClient,
    TimeSourceNotifier,
    (|container: &mut Container| -> Result<Box<Any>> {
        let environment: Arc<Environment> = container.inject()?;

        let args = container.get_arguments().unwrap();
        let channel = ChannelBuilder::new(environment.grpc()).connect(&format!(
            "{}:{}",
            args.value_of("ts-client-host").unwrap(),
            args.value_of("ts-client-port").unwrap(),
        ));

        let instance: Arc<TimeSourceNotifier> = Arc::new(TimeSourceClient::new(channel));
        Ok(Box::new(instance))
    }),
    [
        Arg::with_name("ts-client-host")
            .long("ts-client-host")
            .help("(remote time source backend) Host that the time source client should connect to")
            .takes_value(true)
            .default_value("127.0.0.1"),
        Arg::with_name("ts-client-port")
            .long("ts-client-port")
            .help("(remote time source backend) Port that the time source client should connect to")
            .takes_value(true)
            .default_value("42261")
    ]
);
