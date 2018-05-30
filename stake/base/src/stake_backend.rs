//! Stake escrow backend interface.
use std::fmt;

use ekiden_common::bytes::B256;
use ekiden_common::error::Error;
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
    BadProtoTarget,
    BadEscrowId,
    NoStakeAccount,
    NoEscrowAccount,
    CallerNotEscrowTarget,
    WouldOverflow,
    InsufficientFunds,
    RequestExceedsEscrowedFunds,
}

impl fmt::Display for ErrorCodes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
        // or, alternatively:
        // fmt::Debug::fmt(self, f)
    }
}

pub type AmountType = u64;
/// Dependent code can use either AmountType::max_value() directly or
/// use the AMOUNT_MAX constant; unfortunately, since this is a type
/// alias, we don't seem to be able to have the compiler forbid direct
/// uses of u64::max_value(), which would be bad if/when the type alias
/// ever changes to a narrower type.  An alternative is to wrap it in a
/// struct, but that makes its use very cumbersome.
pub static AMOUNT_MAX: AmountType = AmountType::max_value();

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct EscrowAccountIdType {
    id: U256,
}

impl EscrowAccountIdType {
    pub fn new() -> Self {
        Self { id: U256::from(0) }
    }

    pub fn from_vec(id: Vec<u8>) -> Result<EscrowAccountIdType, Error> {
        if id.len() != 32 {
            return Err(Error::new(ErrorCodes::BadEscrowId.to_string()))
        }
        Ok(EscrowAccountIdType{ id: U256::from_little_endian(&id) })
    }

    pub fn from_slice(slice: &[u8]) -> Result<EscrowAccountIdType, Error> {
        if slice.len() != 32 {
            return Err(Error::new(ErrorCodes::BadEscrowId.to_string()));
        }
        Ok(EscrowAccountIdType{ id: U256::from_little_endian(slice) })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.id.to_vec()
    }

    pub fn incr_mut(&mut self) -> Result<(), Error> {
        let next_id = self.id + U256::from(1);
        if next_id == U256::from(0) {
            return Err(Error::new(ErrorCodes::WouldOverflow.to_string()));
        }
        self.id = next_id;
        Ok(())
    }
}

impl fmt::Display for EscrowAccountIdType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.id)
    }
}

pub struct StakeStatus {
    pub total_stake: AmountType, // Total stake deposited...
    pub escrowed: AmountType,    // ... of which this much is tied up in escrow.
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct EscrowAccountStatus {
    pub id: EscrowAccountIdType,
    pub target: B256,
    pub amount: AmountType,
}

impl EscrowAccountStatus {
    pub fn new(id: EscrowAccountIdType, target: B256, amount: AmountType) -> Self {
        Self { id, target, amount }
    }
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
    ) -> BoxFuture<EscrowAccountIdType>;

    /// Returns a vector of all active escrow accounts created by |msg_sender|.
    fn list_active_escrows(&self, msg_sender: B256) -> BoxFuture<Vec<EscrowAccountStatus>>;

    /// Returns the escrow account data associated with a given |escrow_id|.
    fn fetch_escrow_by_id(&self, escrow_id: EscrowAccountIdType) -> BoxFuture<EscrowAccountStatus>;

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
        escrow_id: EscrowAccountIdType,
        amount_requested: AmountType,
    ) -> BoxFuture<AmountType>;
}
