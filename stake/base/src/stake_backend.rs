//! Stake escrow backend interface.
use std::fmt;

use ekiden_common::bytes::B256;
use ekiden_common::futures::BoxFuture;
use ekiden_common::uint::U256;

// Enum for error strings.  This is the usual ad hoc solution to the
// subclass error type problem: the subclasses need to define their
// own error codes, but the base class designer cannot, in general,
// know what all the various errors might be.  This is defined at the
// service level, so backend implementations should use these, and if
// ever there are backend implementations that want to extend the
// error codes, doing so is an API-breaking change (that requires a
// semantic version bump) -- since adding to the enum means all
// clients must be updated to handle the new values.  Since Error(..)
// is taking the string version of the enum anyway, callers can use
// match guards for the strings that were known when the code was
// written and have a general string handler for a default case which
// handles future extensions.
#[derive(Debug)]
pub enum ErrorCodes {
    InternalError,
    BadProtoSender,
    BadProtoOwner,
    BadProtoDestination,
    BadProtoAmount,
    BadProtoSpender,
    BadProtoTarget,
    BadProtoState,
    BadProtoAddress,
    NoStakeAccount,
    WouldOverflow,
    InsufficientFunds,
    InsufficientAllowance,
    RequestExceedsEscrowedFunds,
    AddressAlreadySet,
}

impl fmt::Display for ErrorCodes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
        // or, alternatively:
        // fmt::Debug::fmt(self, f)
    }
}

pub type AmountType = U256;
// U256 has no constructor that makes a compile-time global constant
// possible, but !AmountType::from(0) works and might even be
// efficient if constant folding works right.

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct EscrowAccountIdType {
    id: U256,
}

pub struct StakeStatus {
    pub total_stake: AmountType, // Total stake deposited...
    pub escrowed: AmountType,    // ... of which this much is tied up in escrow.
}

impl StakeStatus {
    pub fn new(stake: AmountType, escrowed: AmountType) -> Self {
        Self {
            total_stake: stake,
            escrowed: escrowed,
        }
    }
}

/// Stake escrow backend implementing the Ekiden stake/escrow
/// interface.  The AmountType parameters marked ($$) are intended to
/// represent actual token transfers; the other AmountType parameters
/// are requests for values, or status, and do not represent token
/// transfers.
pub trait StakeEscrowBackend: Send + Sync {
    fn link_to_dispute_resolution(&self, address: B256) -> BoxFuture<bool>;

    fn link_to_entity_registry(&self, address: B256) -> BoxFuture<bool>;

    fn get_name(&self) -> BoxFuture<String>;

    fn get_symbol(&self) -> BoxFuture<String>;

    fn get_decimals(&self) -> BoxFuture<u8>;

    fn get_total_supply(&self) -> BoxFuture<AmountType>;

    /// Returns the stake account status (StakeStatus) of the caller |msg_sender|.
    fn get_stake_status(&self, owner: B256) -> BoxFuture<StakeStatus>;

    fn balance_of(&self, owner: B256) -> BoxFuture<AmountType>;

    /// Transfers |amount_requested| from |msg_sender|'s stake account to
    /// the stake account belonging to |target|.  Returns success boolean flag.
    fn transfer(
        &self,
        msg_sender: B256,
        destination_address: B256,
        value: AmountType,
    ) -> BoxFuture<bool>;

    /// Transfers |amount_requested| from |source_address|'s stake
    /// account to the stake account belonging to
    /// |destination_address|, when |msg_sender| has a sufficiently
    /// large approval from |source_address|.  Returns success boolean
    /// flag.
    fn transfer_from(
        &self,
        msg_sender: B256,
        source_address: B256,
        destination_address: B256,
        value: AmountType,
    ) -> BoxFuture<bool>;

    /// Approve by |msg_sender| for |spender| to transferFrom up to |value| tokens.
    fn approve(
        &self,
        msg_sender: B256,
        spender_address: B256,
        value: AmountType,
    ) -> BoxFuture<bool>;

    fn approve_and_call(
        &self,
        msg_sender: B256,
        spender_address: B256,
        value: AmountType,
        extra_data: Vec<u8>,
    ) -> BoxFuture<bool>;

    fn allowance(&self, owner: B256, spender: B256) -> BoxFuture<AmountType>;

    fn burn(&self, msg_sender: B256, value: AmountType) -> BoxFuture<bool>;

    fn burn_from(&self, msg_sender: B256, owner: B256, value: AmountType) -> BoxFuture<bool>;

    /// Adds |escrow_amount| from the caller (|msg_sender|'s) stake
    /// into escrow.  The stake/escrow service will keep the
    /// funds in escrow until the EntityRegistry invokes release_escrow.
    /// Returns the total amount of tokens in escrow so far.
    fn add_escrow(&self, msg_sender: B256, escrow_amount: AmountType) -> BoxFuture<AmountType>;

    /// Returns the escrow amount associated with a given |owner|.
    fn fetch_escrow_amount(&self, owner: B256) -> BoxFuture<AmountType>;

    /// Transfers |amount_requested| of the escrowed amount to the
    /// caller's stake account (stake forfeiture).
    /// Only the DisputeResolution can take escrows.
    /// Returns the amount taken (should be equal to |amount_requested|).
    fn take_escrow(
        &self,
        msg_sender: B256,
        owner: B256,
        amount_requested: AmountType,
    ) -> BoxFuture<AmountType>;

    /// Releases the remainder of the escrowed amount to the owner.
    /// Only the EntityRegistry can release escrows.
    /// Returns the amount of tokens that was released.
    fn release_escrow(&self, msg_sender: B256, owner: B256) -> BoxFuture<AmountType>;
}
