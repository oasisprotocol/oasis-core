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

/// Stake escrow backend implementing the Ekiden stake/escrow
/// interface.  The AmountType parameters marked ($$) are intended to
/// represent actual token transfers; the other AmountType parameters
/// are requests for values, or status, and do not represent token
/// transfers.
pub trait StakeEscrowBackend: Send + Sync {
    /// Deposits |amount| ($$) into the stake account for |msg_sender|.
    fn deposit_stake(&self, msg_sender: B256, amount: AmountType) -> BoxFuture<()>;

    /// Returns the stake account status (StakeStatus) of the caller |msg_sender|.
    fn get_stake_status(&self, msg_sender: B256) -> BoxFuture<StakeStatus>;

    /// Withdraws |amount_requested| ($$) from the stake account
    /// belonging to the caller |msg_sender|.  The value
    /// |amount_requested| cannot exceed available funds (e.g.,
    /// |total_stake - escrowed|) in the stake account.
    fn withdraw_stake(
        &self,
        msg_sender: B256,
        amount_requested: AmountType,
    ) -> BoxFuture<AmountType>;

    /// Allocates |escrow_amount| from the caller (|msg_sender|)'s
    /// stake account to create a new stake account with |target| as
    /// the escrow target.  The stake/escrow service will keep the
    /// funds in escrow until |target| invokes take_and_release_escrow
    /// on the escrow account id returned by this call.
    fn allocate_escrow(
        &self,
        msg_sender: B256,
        target: B256,
        escrow_amount: AmountType,
    ) -> BoxFuture<B256>;

    /// Returns a vector of all active escrow accounts created by |msg_sender|.
    fn list_active_escrows(&self, msg_sender: B256) -> BoxFuture<Vec<api::EscrowData>>;

    /// Returns the escrow account data associated with a given |escrow_id|.
    fn fetch_escrow_by_id(&self, escrow_id: B256) -> BoxFuture<api::EscrowData>;

    /// Dissolves the escrow account |escrow_id|: the |msg_sender|
    /// must be the target of the escrow account, and
    /// |amount_requested| of the escrow amount is returned ($$) to
    /// the caller (e.g., forfeiture).  Any remaining amount is marked
    /// as available in the stake account of the creator of the escrow
    /// account, i.e., it is released from escrow and returned back to
    /// the owner.
    fn take_and_release_escrow(
        &self,
        msg_sender: B256,
        escrow_id: B256,
        amount_requested: AmountType,
    ) -> BoxFuture<AmountType>;
}
