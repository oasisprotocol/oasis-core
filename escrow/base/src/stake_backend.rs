//! Stake escrow backend interface.
use ekiden_common::bytes::B256;
use ekiden_common::futures::BoxFuture;

use ekiden_stake_api as api;

// No numeric_limits<decltype(entry.amount)>::max_value() equivalent yet
pub type AmountType = u64;
// static AMOUNT_MAX : AmountType = <u64>::max_value();
pub static AMOUNT_MAX: AmountType = !(0 as AmountType);

/// Stake escrow backend implementing the Ekiden stake escrow interface.
pub trait StakeEscrowBackend: Send + Sync {
    /// Stake 
    fn deposit_stake(&self, msg_sender: B256, amount: AmountType)
                     -> BoxFuture<()>;
    fn get_stake_status(&self, msg_sender: B256)
                        -> BoxFuture<(AmountType, AmountType)>;
    fn withdraw_stake(&self, msg_sender: B256, amount_requested: AmountType)
                      -> BoxFuture<AmountType>;
    fn allocate_escrow(&self, msg_sender: B256,
                       target: B256, escrow_amount: AmountType)
                       -> BoxFuture<B256>;
    fn list_active_escrows(&self, msg_sender: B256)
                           -> BoxFuture<Vec<api::EscrowData>>;
    fn fetch_escrow_by_id(&self, id: B256)
                          -> BoxFuture<api::EscrowData>;
    fn take_and_release_escrow(&self, msg_sender: B256,
                               id: B256, amount_requested: AmountType)
                               -> BoxFuture<AmountType>;
}
