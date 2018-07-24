use ekiden_common::futures::{BoxFuture, Future};
use ekiden_stake_api as api;
use grpcio::RpcStatusCode::{Internal, InvalidArgument};
use grpcio::{RpcContext, RpcStatus, UnarySink};

use super::stake_backend::AmountType;
use super::stake_backend::ErrorCodes;
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
    fn link_to_dispute_resolution(
        &self,
        ctx: RpcContext,
        req: api::LinkToDisputeResolutionRequest,
        sink: UnarySink<api::LinkToDisputeResolutionResponse>,
    ) {
        let f = move || -> Result<BoxFuture<bool>, Error> {
            let address = match B256::try_from(req.get_address()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoAddress.to_string())),
                Ok(t) => t,
            };
            Ok(self.inner.link_to_dispute_resolution(address))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(b) => {
                    let mut r = api::LinkToDisputeResolutionResponse::new();
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

    fn link_to_entity_registry(
        &self,
        ctx: RpcContext,
        req: api::LinkToEntityRegistryRequest,
        sink: UnarySink<api::LinkToEntityRegistryResponse>,
    ) {
        let f = move || -> Result<BoxFuture<bool>, Error> {
            let address = match B256::try_from(req.get_address()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoAddress.to_string())),
                Ok(t) => t,
            };
            Ok(self.inner.link_to_entity_registry(address))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(b) => {
                    let mut r = api::LinkToEntityRegistryResponse::new();
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

    fn add_escrow(
        &self,
        ctx: RpcContext,
        req: api::AddEscrowRequest,
        sink: UnarySink<api::AddEscrowResponse>,
    ) {
        let f = move || -> Result<BoxFuture<AmountType>, Error> {
            let s = match B256::try_from(req.get_msg_sender()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoSender.to_string())),
                Ok(s) => s,
            };
            let a = AmountType::from_little_endian(req.get_escrow_amount());
            Ok(self.inner.add_escrow(s, a))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(tesf) => {
                    let mut r = api::AddEscrowResponse::new();
                    r.set_total_escrow_so_far(tesf.to_vec());
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

    fn fetch_escrow_amount(
        &self,
        ctx: RpcContext,
        req: api::FetchEscrowAmountRequest,
        sink: UnarySink<api::FetchEscrowAmountResponse>,
    ) {
        let f = move || -> Result<BoxFuture<AmountType>, Error> {
            let owner = match B256::try_from(req.get_owner()) {
                Err(e) => return Err(e),
                Ok(o) => o,
            };
            Ok(self.inner.fetch_escrow_amount(owner))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(escrow_amount) => {
                    let mut r = api::FetchEscrowAmountResponse::new();
                    r.set_amount(escrow_amount.to_vec());
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

    fn take_escrow(
        &self,
        ctx: RpcContext,
        req: api::TakeEscrowRequest,
        sink: UnarySink<api::TakeEscrowResponse>,
    ) {
        let f = move || -> Result<BoxFuture<AmountType>, Error> {
            let s = match B256::try_from(req.get_msg_sender()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoSender.to_string())),
                Ok(s) => s,
            };
            let owner = match B256::try_from(req.get_owner()) {
                Err(e) => return Err(e),
                Ok(o) => o,
            };
            let a = AmountType::from_little_endian(req.get_amount_requested());
            Ok(self.inner.take_escrow(s, owner, a))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(amount_taken) => {
                    let mut r = api::TakeEscrowResponse::new();
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

    fn release_escrow(
        &self,
        ctx: RpcContext,
        req: api::ReleaseEscrowRequest,
        sink: UnarySink<api::ReleaseEscrowResponse>,
    ) {
        let f = move || -> Result<BoxFuture<AmountType>, Error> {
            let s = match B256::try_from(req.get_msg_sender()) {
                Err(_e) => return Err(Error::new(ErrorCodes::BadProtoSender.to_string())),
                Ok(s) => s,
            };
            let owner = match B256::try_from(req.get_owner()) {
                Err(e) => return Err(e),
                Ok(o) => o,
            };
            Ok(self.inner.release_escrow(s, owner))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(amount_returned) => {
                    let mut r = api::ReleaseEscrowResponse::new();
                    r.set_amount_returned(amount_returned.to_vec());
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
