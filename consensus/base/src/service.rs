use std::convert::{Into, TryFrom};

use ekiden_common::bytes::B256;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, BoxFuture, Future, Stream};
use ekiden_common::signature::{Signature, Signed};
use ekiden_consensus_api as api;
use grpcio::{RpcContext, RpcStatus, ServerStreamingSink, UnarySink, WriteFlags};
use grpcio::RpcStatusCode::{Internal, InvalidArgument};

use super::backend::{ConsensusBackend, Event};
use block::Block;
use commitment::{Commitment, Reveal};
use header::Header;

pub struct ConsensusService<T>
where
    T: ConsensusBackend,
{
    inner: T,
}

impl<T> ConsensusService<T>
where
    T: ConsensusBackend,
{
    pub fn new(backend: T) -> Self {
        Self { inner: backend }
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

impl<T> api::Consensus for ConsensusService<T>
where
    T: ConsensusBackend,
{
    fn get_latest_block(
        &self,
        ctx: RpcContext,
        _req: api::LatestBlockRequest,
        sink: UnarySink<api::LatestBlockResponse>,
    ) {
        let f = move || -> Result<BoxFuture<Block>, Error> { Ok(self.inner.get_latest_block()) };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(block) => {
                    let mut resp = api::LatestBlockResponse::new();
                    resp.set_block(block.into());
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

    fn get_blocks(
        &self,
        ctx: RpcContext,
        _req: api::BlockRequest,
        sink: ServerStreamingSink<api::BlockResponse>,
    ) {
        let f = self.inner
            .get_blocks()
            .map(|res| -> (api::BlockResponse, WriteFlags) {
                let mut r = api::BlockResponse::new();
                r.set_block(res.into());
                (r, WriteFlags::default())
            });
        ctx.spawn(f.forward(sink).then(|_f| future::ok(())));
    }

    fn get_events(
        &self,
        ctx: RpcContext,
        _req: api::EventRequest,
        sink: ServerStreamingSink<api::EventResponse>,
    ) {
        let f = self.inner
            .get_events()
            .map(|res| -> (api::EventResponse, WriteFlags) {
                let mut r = api::EventResponse::new();
                match res {
                    Event::CommitmentsReceived => {
                        r.set_event(api::EventResponse_Event::COMMITMENTSRECEIVED)
                    }
                    Event::RoundFailed(_) => r.set_event(api::EventResponse_Event::ROUNDFAILED),
                };
                (r, WriteFlags::default())
            });
        ctx.spawn(f.forward(sink).then(|_f| future::ok(())));
    }

    fn commit(
        &self,
        ctx: RpcContext,
        req: api::CommitRequest,
        sink: UnarySink<api::CommitResponse>,
    ) {
        let f = move || -> Result<BoxFuture<()>, Error> {
            let commitment = Commitment::try_from(req.get_commitment().clone())?;
            Ok(self.inner.commit(commitment))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(()) => Ok(api::CommitResponse::new()),
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

    fn reveal(
        &self,
        ctx: RpcContext,
        req: api::RevealRequest,
        sink: UnarySink<api::RevealResponse>,
    ) {
        let f = move || -> Result<BoxFuture<()>, Error> {
            let header = Header::try_from(req.get_header().clone())?;
            let nonce = B256::from(req.get_nonce());
            let s = Signature::try_from(req.get_signature().clone())?;
            Ok(self.inner.reveal(Reveal {
                value: header,
                nonce: nonce,
                signature: s,
            }))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(()) => Ok(api::RevealResponse::new()),
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

    fn submit(
        &self,
        ctx: RpcContext,
        req: api::SubmitRequest,
        sink: UnarySink<api::SubmitResponse>,
    ) {
        let f = move || -> Result<BoxFuture<()>, Error> {
            let block = Block::try_from(req.get_block().clone())?;
            let s = Signature::try_from(req.get_signature().clone())?;
            Ok(self.inner.submit(Signed::from_parts(block, s)))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(()) => Ok(api::SubmitResponse::new()),
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
}
