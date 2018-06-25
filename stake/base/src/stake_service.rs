use ekiden_common::futures::{BoxFuture, Future};
use ekiden_stake_api as api;
use grpcio::RpcStatusCode::{Internal, InvalidArgument};
use grpcio::{RpcContext, RpcStatus, UnarySink};

use super::stake_backend::AmountType;
use super::stake_backend::ErrorCodes;
use super::stake_backend::EscrowAccountIdType;
use super::stake_backend::EscrowAccountIterator;
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
    fn get_name(
        &self,
        ctx: RpcContext,
        _req: api::GetNameRequest,
        sink: UnarySink<api::GetNameResponse>,
    ) {
        let f = move || -> Result<BoxFuture<String>, Error> { Ok(self.inner.get_name()) };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(name) => {
                    let mut r = api::GetNameResponse::new();
                    r.set_name(name);
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

    fn get_symbol(
        &self,
        ctx: RpcContext,
        _req: api::GetSymbolRequest,
        sink: UnarySink<api::GetSymbolResponse>,
    ) {
        let f = move || -> Result<BoxFuture<String>, Error> { Ok(self.inner.get_symbol()) };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(symbol) => {
                    let mut r = api::GetSymbolResponse::new();
                    r.set_symbol(symbol);
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

    fn get_decimals(
        &self,
        ctx: RpcContext,
        _req: api::GetDecimalsRequest,
        sink: UnarySink<api::GetDecimalsResponse>,
    ) {
        let f = move || -> Result<BoxFuture<u8>, Error> { Ok(self.inner.get_decimals()) };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(decimals) => {
                    let mut r = api::GetDecimalsResponse::new();
                    r.set_decimals(decimals as u32);
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

    fn get_total_supply(
        &self,
        ctx: RpcContext,
        _req: api::GetTotalSupplyRequest,
        sink: UnarySink<api::GetTotalSupplyResponse>,
    ) {
        let f =
            move || -> Result<BoxFuture<AmountType>, Error> { Ok(self.inner.get_total_supply()) };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(supply) => {
                    let mut r = api::GetTotalSupplyResponse::new();
                    r.set_total_supply(supply.to_vec());
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

    fn get_stake_status(
        &self,
        ctx: RpcContext,
        req: api::GetStakeStatusRequest,
        sink: UnarySink<api::GetStakeStatusResponse>,
    ) {
        let f = move || -> Result<BoxFuture<StakeStatus>, Error> {
            match B256::try_from(req.get_owner()) {
                Err(_e) => Err(Error::new(ErrorCodes::BadProtoSender.to_string())),
                Ok(owner) => Ok(self.inner.get_stake_status(owner)),
            }
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(status) => {
                    let mut r = api::GetStakeStatusResponse::new();
                    r.set_total_stake(status.total_stake.to_vec());
                    r.set_escrowed_stake(status.escrowed.to_vec());
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

    fn balance_of(
        &self,
        ctx: RpcContext,
        req: api::BalanceOfRequest,
        sink: UnarySink<api::BalanceOfResponse>,
    ) {
        let f = move || -> Result<BoxFuture<AmountType>, Error> {
            match B256::try_from(req.get_owner()) {
                Err(_e) => Err(Error::new(ErrorCodes::BadProtoSender.to_string())),
                Ok(owner) => Ok(self.inner.balance_of(owner)),
            }
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(amount) => {
                    let mut r = api::BalanceOfResponse::new();
                    r.set_available_balance(amount.to_vec());
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

    fn transfer(
        &self,
        ctx: RpcContext,
        req: api::TransferRequest,
        sink: UnarySink<api::TransferResponse>,
    ) {
        let f = move || -> Result<BoxFuture<bool>, Error> {
            let sender = match B256::try_from(req.get_msg_sender()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoSender.to_string())),
                Ok(s) => s,
            };
            let destination_address = match B256::try_from(req.get_destination_address()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoTarget.to_string())),
                Ok(t) => t,
            };
            let value = AmountType::from_little_endian(req.get_value());
            Ok(self.inner.transfer(sender, destination_address, value))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(b) => {
                    let mut r = api::TransferResponse::new();
                    r.set_success(b);
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

    fn transfer_from(
        &self,
        ctx: RpcContext,
        req: api::TransferFromRequest,
        sink: UnarySink<api::TransferFromResponse>,
    ) {
        let f = move || -> Result<BoxFuture<bool>, Error> {
            let sender = match B256::try_from(req.get_msg_sender()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoSender.to_string())),
                Ok(s) => s,
            };
            let src = match B256::try_from(req.get_source_address()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoOwner.to_string())),
                Ok(s) => s,
            };
            let dst = match B256::try_from(req.get_destination_address()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoDestination.to_string())),
                Ok(d) => d,
            };
            let value = AmountType::from_little_endian(req.get_value());
            Ok(self.inner.transfer_from(sender, src, dst, value))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(b) => {
                    let mut r = api::TransferFromResponse::new();
                    r.set_success(b);
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

    fn approve(
        &self,
        ctx: RpcContext,
        req: api::ApproveRequest,
        sink: UnarySink<api::ApproveResponse>,
    ) {
        let f = move || -> Result<BoxFuture<bool>, Error> {
            let s = match B256::try_from(req.get_msg_sender()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoSender.to_string())),
                Ok(s) => s,
            };
            let spender = match B256::try_from(req.get_spender_address()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoSpender.to_string())),
                Ok(s) => s,
            };
            let amt = AmountType::from_little_endian(req.get_value());
            Ok(self.inner.approve(s, spender, amt))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(b) => {
                    let mut r = api::ApproveResponse::new();
                    r.set_success(b);
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

    fn approve_and_call(
        &self,
        ctx: RpcContext,
        req: api::ApproveAndCallRequest,
        sink: UnarySink<api::ApproveAndCallResponse>,
    ) {
        let f = move || -> Result<BoxFuture<bool>, Error> {
            let s = match B256::try_from(req.get_msg_sender()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoSender.to_string())),
                Ok(s) => s,
            };
            let spender = match B256::try_from(req.get_spender_address()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoSpender.to_string())),
                Ok(s) => s,
            };
            let amt = AmountType::from_little_endian(req.get_value());
            let extra_data = req.get_extra_data().to_vec();
            Ok(self.inner.approve_and_call(s, spender, amt, extra_data))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(b) => {
                    let mut r = api::ApproveAndCallResponse::new();
                    r.set_success(b);
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

    fn allowance(
        &self,
        ctx: RpcContext,
        req: api::AllowanceRequest,
        sink: UnarySink<api::AllowanceResponse>,
    ) {
        let f = move || -> Result<BoxFuture<AmountType>, Error> {
            let owner = match B256::try_from(req.get_owner_address()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoOwner.to_string())),
                Ok(o) => o,
            };
            let spender = match B256::try_from(req.get_spender_address()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoSpender.to_string())),
                Ok(s) => s,
            };
            Ok(self.inner.allowance(owner, spender))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(b) => {
                    let mut r = api::AllowanceResponse::new();
                    r.set_remaining(b.to_vec());
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

    fn burn(&self, ctx: RpcContext, req: api::BurnRequest, sink: UnarySink<api::BurnResponse>) {
        let f = move || -> Result<BoxFuture<bool>, Error> {
            let sender = match B256::try_from(req.get_msg_sender()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoSender.to_string())),
                Ok(s) => s,
            };
            let amt = AmountType::from_little_endian(req.get_value());
            Ok(self.inner.burn(sender, amt))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(b) => {
                    let mut r = api::BurnResponse::new();
                    r.set_success(b);
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

    fn burn_from(
        &self,
        ctx: RpcContext,
        req: api::BurnFromRequest,
        sink: UnarySink<api::BurnFromResponse>,
    ) {
        let f = move || -> Result<BoxFuture<bool>, Error> {
            let sender = match B256::try_from(req.get_msg_sender()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoSender.to_string())),
                Ok(s) => s,
            };
            let owner = match B256::try_from(req.get_owner_address()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoOwner.to_string())),
                Ok(o) => o,
            };
            let amt = AmountType::from_little_endian(req.get_value());
            Ok(self.inner.burn_from(sender, owner, amt))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(b) => {
                    let mut r = api::BurnFromResponse::new();
                    r.set_success(b);
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
                Ok(s) => s,
            };
            let t = match B256::try_from(req.get_target()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoTarget.to_string())),
                Ok(t) => t,
            };
            let a = AmountType::from_little_endian(req.get_escrow_amount());
            let aux = match B256::try_from(req.get_aux()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoAux.to_string())),
                Ok(aux) => aux,
            };
            Ok(self.inner.allocate_escrow(s, t, a, aux))
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

    fn list_active_escrows_iterator(
        &self,
        ctx: RpcContext,
        req: api::ListActiveEscrowsIteratorRequest,
        sink: UnarySink<api::ListActiveEscrowsIteratorResponse>,
    ) {
        let f = move || -> Result<BoxFuture<EscrowAccountIterator>, Error> {
            match B256::try_from(req.get_owner()) {
                Err(_e) => Err(Error::new(ErrorCodes::BadProtoOwner.to_string())),
                Ok(s) => Ok(self.inner.list_active_escrows_iterator(s)),
            }
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(it) => {
                    let mut r = api::ListActiveEscrowsIteratorResponse::new();
                    r.set_has_next(it.has_next);
                    // it.owner == req.get_owner()
                    r.set_state(it.state.to_vec());
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

    fn list_active_escrows_get(
        &self,
        ctx: RpcContext,
        req: api::ListActiveEscrowsGetRequest,
        sink: UnarySink<api::ListActiveEscrowsGetResponse>,
    ) {
        let f =
            move || -> Result<BoxFuture<(EscrowAccountStatus, EscrowAccountIterator)>, Error> {
                let owner = match B256::try_from(req.get_owner()) {
                    Err(_e) => return Err(Error::new(ErrorCodes::BadProtoOwner.to_string())),
                    Ok(s) => s,
                };
                let state = match B256::try_from(req.get_state()) {
                    Err(_e) => return Err(Error::new(ErrorCodes::BadProtoState.to_string())),
                    Ok(s) => s,
                };
                let it = EscrowAccountIterator::new(true, owner, state);
                Ok(self.inner.list_active_escrows_get(it))
            };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok((status, new_it)) => {
                    let mut r = api::ListActiveEscrowsGetResponse::new();
                    r.set_escrow_id(status.id.to_vec());
                    r.set_target(status.target.to_vec());
                    r.set_amount(status.amount.to_vec());
                    r.set_aux(status.aux.to_vec());
                    r.set_has_next(new_it.has_next);
                    // new_it.owner == it.owner
                    r.set_state(new_it.state.to_vec());
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
                    let mut r = api::FetchEscrowByIdResponse::new();
                    r.set_escrow_id(escrow.id.to_vec());
                    r.set_target(escrow.target.to_vec());
                    r.set_amount(escrow.amount.to_vec());
                    r.set_aux(escrow.aux.to_vec());
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
        let f = move || -> Result<BoxFuture<AmountType>, Error> {
            let s = match B256::try_from(req.get_msg_sender()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoSender.to_string())),
                Ok(s) => s,
            };
            let i = match EscrowAccountIdType::from_slice(req.get_escrow_id()) {
                Err(e) => return Err(e),
                Ok(i) => i,
            };
            let a = AmountType::from_little_endian(req.get_amount_requested());
            Ok(self.inner.take_and_release_escrow(s, i, a))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(amount_taken) => {
                    let mut r = api::TakeAndReleaseEscrowResponse::new();
                    r.set_amount_taken(amount_taken.to_vec());
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
