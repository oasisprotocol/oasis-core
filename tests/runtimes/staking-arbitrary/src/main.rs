extern crate failure;

use std::sync::Arc;

use failure::Fallible;
use oasis_core_runtime::{
    common::{
        roothash::{AdjustmentOp, RoothashMessage},
        version::Version,
    },
    rak::RAK,
    register_runtime_txn_methods,
    transaction::Context as TxnContext,
    version_from_cargo, Protocol, RpcDemux, RpcDispatcher, TxnDispatcher,
};
use staking_arbitrary_api::{with_api, AccountAmount};

fn increase(args: &AccountAmount, ctx: &mut TxnContext) -> Fallible<()> {
    ctx.send_roothash_message(RoothashMessage::StakingGeneralAdjustmentRoothashMessage {
        account: args.account,
        op: AdjustmentOp::INCREASE,
        amount: args.amount.clone(),
    });
    return Ok(());
}

fn decrease(args: &AccountAmount, ctx: &mut TxnContext) -> Fallible<()> {
    ctx.send_roothash_message(RoothashMessage::StakingGeneralAdjustmentRoothashMessage {
        account: args.account,
        op: AdjustmentOp::DECREASE,
        amount: args.amount.clone(),
    });
    return Ok(());
}

fn register(
    _protocol: &Arc<Protocol>,
    _rak: &Arc<RAK>,
    _rpc_demux: &mut RpcDemux,
    _rpc: &mut RpcDispatcher,
    txn: &mut TxnDispatcher,
) {
    with_api! {
        register_runtime_txn_methods!(txn, api);
    }
}

fn main() {
    oasis_core_runtime::start_runtime(Some(Box::new(register)), version_from_cargo!());
}
