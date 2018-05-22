//! Stake escrow backend interface.
use ekiden_common::bytes::B256;
use ekiden_common::futures::{BoxFuture, Future};

use ekiden_stake_api as api;

// No numeric_limits<decltype(entry.amount)>::max_value() equivalent yet
pub type AmountType = u64;
pub static AMOUNT_MAX: AmountType = AmountType::max_value();

pub struct StakeStatus {
    pub total_stake: AmountType, // Total stake deposited...
    pub escrowed: AmountType,    // ... of which this much is tied up in escrow.
}

/// Stake escrow backend implementing the Ekiden stake escrow interface.
pub trait StakeEscrowBackend: Send + Sync {
    /// Stake
    fn deposit_stake(&self, msg_sender: B256, amount: AmountType) -> BoxFuture<()>;
    fn get_stake_status(&self, msg_sender: B256) -> BoxFuture<StakeStatus>;
    fn withdraw_stake(
        &self,
        msg_sender: B256,
        amount_requested: AmountType,
    ) -> BoxFuture<AmountType>;
    fn allocate_escrow(
        &self,
        msg_sender: B256,
        target: B256,
        escrow_amount: AmountType,
    ) -> BoxFuture<B256>;
    fn list_active_escrows(&self, msg_sender: B256) -> BoxFuture<Vec<api::EscrowData>>;
    fn fetch_escrow_by_id(&self, escrow_id: B256) -> BoxFuture<api::EscrowData>;
    fn take_and_release_escrow(
        &self,
        msg_sender: B256,
        escrow_id: B256,
        amount_requested: AmountType,
    ) -> BoxFuture<AmountType>;
}
