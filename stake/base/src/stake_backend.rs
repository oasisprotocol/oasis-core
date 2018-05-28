//! Stake escrow backend interface.
use ekiden_common::bytes::B256;
use ekiden_common::futures::BoxFuture;

use ekiden_stake_api as api;

pub type AmountType = u64;
/// Dependent code can use either AmountType::max_value() directly or
/// use the AMOUNT_MAX constant; unfortunately, since this is a type
/// alias, we don't seem to be able to have the compiler forbid direct
/// uses of u64::max_value(), which would be bad if/when the type alias
/// ever changes to a narrower type.  An alternative is to wrap it in a
/// struct, but that makes its use very cumbersome.
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
