use ekiden_common::futures::{BoxFuture, Future};
use ekiden_stake_api as api;
use grpcio::RpcStatusCode::{Internal, InvalidArgument};
use grpcio::{RpcContext, RpcStatus, UnarySink};

use super::stake_backend::ErrorCodes;
use super::stake_backend::EscrowAccountIdType;
use super::stake_backend::EscrowAccountStatus;
use super::stake_backend::StakeEscrowBackend;
use super::stake_backend::StakeStatus;
use ekiden_common::bytes::B256;
use ekiden_common::error::Error;

pub struct StakeEscrowService<T>
where
    T: StakeEscrowBackend,
{
    inner: T,
}

impl<T> StakeEscrowService<T>
where
    T: StakeEscrowBackend,
{
    pub fn new(backend: T) -> Self {
        Self { inner: backend }
    }
}

macro_rules! invalid {
    ($sink:ident, $code:ident, $e:expr) => {
        $sink.fail(RpcStatus::new($code, Some($e.description().to_owned())))
    };
}

impl<T> api::Stake for StakeEscrowService<T>
where
    T: StakeEscrowBackend,
{
    fn deposit_stake(
        &self,
        ctx: RpcContext,
        req: api::DepositStakeRequest,
        sink: UnarySink<api::DepositStakeResponse>,
    ) {
        let f = move || -> Result<BoxFuture<()>, Error> {
            match B256::try_from(req.get_msg_sender()) {
                Err(_e) => Err(Error::new(ErrorCodes::BadProtoSender.to_string())),
                Ok(s) => {
                    let a = req.get_amount();
                    Ok(self.inner.deposit_stake(s, a))
                }
            }
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
        let f = move || -> Result<BoxFuture<StakeStatus>, Error> {
            match B256::try_from(req.get_msg_sender()) {
                Err(_e) => Err(Error::new(ErrorCodes::BadProtoSender.to_string())),
                Ok(s) => Ok(self.inner.get_stake_status(s)),
            }
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(status) => {
                    let mut r = api::GetStakeStatusResponse::new();
                    r.set_total_stake(status.total_stake);
                    r.set_escrowed_stake(status.escrowed);
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
            match B256::try_from(req.get_msg_sender()) {
                Err(_e) => Err(Error::new(ErrorCodes::BadProtoSender.to_string())),
                Ok(s) => Ok(self.inner.withdraw_stake(s, req.get_amount_requested())),
            }
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
        let f = move || -> Result<BoxFuture<EscrowAccountIdType>, Error> {
            let s = match B256::try_from(req.get_msg_sender()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoSender.to_string())),
                Ok(s) => s
            };
            let t = match B256::try_from(req.get_target()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoTarget.to_string())),
                Ok(t) => t
            };
            let a = req.get_escrow_amount();
            Ok(self.inner.allocate_escrow(s, t, a))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(id) => {
                    let mut r = api::AllocateEscrowResponse::new();
                    r.set_escrow_id(id.to_vec());
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
        let f = move || -> Result<BoxFuture<Vec<EscrowAccountStatus>>, Error> {
            match B256::try_from(req.get_msg_sender()) {
                Err(_e) => Err(Error::new(ErrorCodes::BadProtoSender.to_string())),
                Ok(s) => Ok(self.inner.list_active_escrows(s)),
            }
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(escrows) => {
                    let mut r = api::ListActiveEscrowsResponse::new();
                    r.set_escrows(escrows.iter().map(
                        |e| {
                            let mut ae = api::EscrowData::new();
                            ae.set_escrow_id(e.id.to_vec());
                            ae.set_entity(e.target.to_vec());
                            ae.set_amount(e.amount);
                            ae
                        }).collect()
                    );
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
        let f = move || -> Result<BoxFuture<EscrowAccountStatus>, Error> {
            let id = match EscrowAccountIdType::from_slice(req.get_escrow_id()) {
                Err(e) => return Err(e),
                Ok(i) => i,
            };
            Ok(self.inner.fetch_escrow_by_id(id))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(escrow) => {
                    let mut ed = api::EscrowData::new();
                    ed.set_escrow_id(escrow.id.to_vec());
                    ed.set_entity(escrow.target.to_vec());
                    ed.set_amount(escrow.amount);
                    let mut r = api::FetchEscrowByIdResponse::new();
                    r.set_escrow(ed);
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
            let s = match B256::try_from(req.get_msg_sender()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoSender.to_string())),
                Ok(s) => s,
            };
            let i = match EscrowAccountIdType::from_slice(req.get_escrow_id()) {
                Err(e) => return Err(e),
                Ok(i) => i,
            };
            let a = req.get_amount_requested();
            Ok(self.inner.take_and_release_escrow(s, i, a))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(amount_taken) => {
                    let mut r = api::TakeAndReleaseEscrowResponse::new();
                    r.set_amount_taken(amount_taken);
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
