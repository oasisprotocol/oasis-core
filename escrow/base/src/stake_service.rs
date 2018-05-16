use std::convert::{Into, TryFrom};

use ekiden_common::futures::{BoxFuture, Future};
use ekiden_stake_api as api;
use grpcio::{RpcContext, RpcStatus, UnarySink};
use grpcio::RpcStatusCode::{Internal, InvalidArgument};

use super::stake_backend::EntityStakeBackend;
use ekiden_common::bytes::B256;
use ekiden_common::entity::Entity;
use ekiden_common::error::Error;

pub struct EntityStakeService<T>
where
    T: EntityStakeBackend,
{
    inner: T,
}

impl<T> EntityStakeService<T>
where
    T: EntityStakeBackend,
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

impl<T> api::Stake for EntityStakeService<T>
where
    T: EntityStakeBackend,
{
    fn deposit_stake(
        &self,
        ctx: RpcContext,
        req: api::DepositStakeRequest,
        sink: UnarySink<api::DepositStakeResponse>,
    ) {
        let f = move || -> Result<BoxFuture<()>, Error> {
            let s = Entity::try_from(req.get_msg_sender().clone())?;
            let a = req.get_amount();
            Ok(self.inner.deposit_stake(s, a))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(()) => Ok(api::DepositStakeResponse::new()),
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

    fn get_stake_status(
        &self,
        ctx: RpcContext,
        req: api::GetStakeStatusRequest,
        sink: UnarySink<api::GetStakeStatusResponse>,
    ) {
        let f = move || -> Result<BoxFuture<(u64, u64)>, Error> {
            let s = Entity::try_from(req.get_msg_sender().clone())?;
            Ok(self.inner.get_stake_status(s))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok((total_stake, escrowed_stake)) => {
                    let mut r = api::GetStakeStatusResponse::new();
                    r.set_total_stake(total_stake);
                    r.set_escrowed_stake(escrowed_stake);
                    Ok(r)
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

    fn withdraw_stake(
        &self,
        ctx: RpcContext,
        req: api::WithdrawStakeRequest,
        sink: UnarySink<api::WithdrawStakeResponse>,
    ) {
        let f = move || -> Result<BoxFuture<(u64)>, Error> {
            let s = Entity::try_from(req.get_msg_sender().clone())?;
            let a = req.get_amount_requested();
            Ok(self.inner.withdraw_stake(s, a))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(amount_returned) => {
                    let mut r = api::WithdrawStakeResponse::new();
                    r.set_amount_returned(amount_returned);
                    Ok(r)
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

    fn allocate_escrow(
        &self,
        ctx: RpcContext,
        req: api::AllocateEscrowRequest,
        sink: UnarySink<api::AllocateEscrowResponse>,
    ) {
        let f = move || -> Result<BoxFuture<B256>, Error> {
            let s = Entity::try_from(req.get_msg_sender().clone())?;
            let e = Entity::try_from(req.get_entity().clone())?;
            let a = req.get_escrow_amount();
            Ok(self.inner.allocate_escrow(s, e, a))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(id) => {
                    let mut r = api::AllocateEscrowResponse::new();
                    r.set_id(id.to_vec());
                    Ok(r)
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

    fn list_active_escrows(
        &self,
        ctx: RpcContext,
        req: api::ListActiveEscrowsRequest,
        sink: UnarySink<api::ListActiveEscrowsResponse>,
    ) {
        let f = move || -> Result<BoxFuture<(Vec<api::EscrowData>)>, Error> {
            let s = Entity::try_from(req.get_msg_sender().clone())?;
            Ok(self.inner.list_active_escrows(s))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(escrows) => {
                    let mut r = api::ListActiveEscrowsResponse::new();
                    r.set_escrows(escrows.iter().map(|e| e.to_owned().into()).collect());
                    Ok(r)
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

    fn fetch_escrow_by_id(
        &self,
        ctx: RpcContext,
        req: api::FetchEscrowByIdRequest,
        sink: UnarySink<api::FetchEscrowByIdResponse>,
    ) {
        let f = move || -> Result<BoxFuture<api::EscrowData>, Error> {
            let i = B256::from_slice(req.get_id());
            Ok(self.inner.fetch_escrow_by_id(i))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(escrow) => {
                    let mut r = api::FetchEscrowByIdResponse::new();
                    r.set_escrow(escrow);
                    Ok(r)
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

    fn take_and_release_escrow(
        &self,
        ctx: RpcContext,
        req: api::TakeAndReleaseEscrowRequest,
        sink: UnarySink<api::TakeAndReleaseEscrowResponse>,
    ) {
        let f = move || -> Result<BoxFuture<u64>, Error> {
            let s = Entity::try_from(req.get_msg_sender().clone())?;
            let i = B256::from_slice(req.get_id());
            let a = req.get_amount_requested();
            Ok(self.inner.take_and_release_escrow(s, i, a))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(amount_returned) => {
                    let mut r = api::TakeAndReleaseEscrowResponse::new();
                    r.set_amount_returned(amount_returned);
                    Ok(r)
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
}
