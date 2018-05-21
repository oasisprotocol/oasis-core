use std::sync::Arc;

use ekiden_beacon_api as api;
use ekiden_common::bytes::B256;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, BoxFuture, Future, Stream};
use grpcio::{RpcContext, RpcStatus, ServerStreamingSink, UnarySink, WriteFlags};
use grpcio::RpcStatusCode::{Internal, InvalidArgument};

use super::backend::RandomBeacon;

#[derive(Clone)]
pub struct BeaconService {
    inner: Arc<RandomBeacon>,
}

impl BeaconService {
    pub fn new(backend: Arc<RandomBeacon>) -> Self {
        Self { inner: backend }
    }
}

macro_rules! invalid {
    ($sink:ident, $code:ident, $e:expr) => {
        $sink.fail(RpcStatus::new($code, Some($e.description().to_owned())))
    };
}

impl api::Beacon for BeaconService {
    fn get_beacon(
        &self,
        ctx: RpcContext,
        req: api::BeaconRequest,
        sink: UnarySink<api::BeaconResponse>,
    ) {
        let f = move || -> Result<BoxFuture<B256>, Error> {
            let epoch = req.get_epoch();
            Ok(self.inner.get_beacon(epoch))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(beacon) => {
                    let mut resp = api::BeaconResponse::new();
                    resp.set_beacon(beacon.to_vec());
                    Ok(resp)
                }
                Err(e) => Err(e),
            }),
            Err(e) => {
                ctx.spawn(invalid!(sink, InvalidArgument, e).map_err(|_e| ()));
                return;
            }
        };
        ctx.spawn(f.then(move |r| match r {
            Ok(ret) => sink.success(ret),
            Err(e) => invalid!(sink, Internal, e),
        }).map_err(|_e| ()));
    }

    fn watch_beacons(
        &self,
        ctx: RpcContext,
        _req: api::WatchBeaconRequest,
        sink: ServerStreamingSink<api::WatchBeaconResponse>,
    ) {
        let f = self.inner
            .watch_beacons()
            .map(|res| -> (api::WatchBeaconResponse, WriteFlags) {
                let mut r = api::WatchBeaconResponse::new();
                r.set_epoch(res.0);
                r.set_beacon(res.1.to_vec());
                (r, WriteFlags::default())
            });
        ctx.spawn(f.forward(sink).then(|_f| future::ok(())));
    }
}
