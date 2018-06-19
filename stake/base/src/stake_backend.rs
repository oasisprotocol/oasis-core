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
    BadProtoOwner,
    BadProtoDestination,
    BadProtoAmount,
    BadProtoSpender,
    BadProtoTarget,
    BadProtoState,
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

pub type AmountType = U256;
// U256 has no constructor that makes a compile-time global constant
// possible, but !AmountType::from(0) works and might even be
// efficient if constant folding works right.

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct EscrowAccountIdType {
    id: U256,
}

// The new() and incr_mut methods are really only used from the dummy impl.
impl EscrowAccountIdType {
    pub fn new() -> Self {
        // In EVM, the all-zero address is special.
        let mut ea_id = Self { id: U256::from(0) };
        match ea_id.incr_mut() {
            Err(e) => panic!(e),
            Ok(o) => o,
        };
        ea_id
    }

    pub fn from_vec(id: Vec<u8>) -> Result<EscrowAccountIdType, Error> {
        if id.len() != 32 {
            return Err(Error::new(ErrorCodes::BadEscrowId.to_string()));
        }
        Ok(EscrowAccountIdType {
            id: U256::from_little_endian(&id),
        })
    }

    pub fn from_slice(slice: &[u8]) -> Result<EscrowAccountIdType, Error> {
        if slice.len() != 32 {
            return Err(Error::new(ErrorCodes::BadEscrowId.to_string()));
        }
        Ok(EscrowAccountIdType {
            id: U256::from_little_endian(slice),
        })
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
    pub aux: B256,
}

impl EscrowAccountStatus {
    pub fn new(id: EscrowAccountIdType, target: B256, amount: AmountType, aux: B256) -> Self {
        Self { id, target, amount, aux }
    }
}

pub struct EscrowAccountIterator {
    pub has_next: bool,
    pub owner: B256,
    pub state: B256,
}

impl EscrowAccountIterator {
    pub fn new(has_next: bool, owner: B256, state: B256) -> Self {
        Self { has_next, owner, state }
    }
}

/// Stake escrow backend implementing the Ekiden stake/escrow
/// interface.  The AmountType parameters marked ($$) are intended to
/// represent actual token transfers; the other AmountType parameters
/// are requests for values, or status, and do not represent token
/// transfers.
pub trait StakeEscrowBackend: Send + Sync {
    fn get_name(&self) -> BoxFuture<String>;

    fn get_symbol(&self) -> BoxFuture<String>;

    fn get_decimals(&self) -> BoxFuture<u8>;

    fn get_total_supply(&self) -> BoxFuture<AmountType>;

    /// Returns the stake account status (StakeStatus) of the caller |msg_sender|.
    fn get_stake_status(&self, owner: B256) -> BoxFuture<StakeStatus>;

    fn balance_of(&self, owner: B256) -> BoxFuture<AmountType>;

    /// Transfers |amount_requested| from |msg_sender|'s stake account to
    /// the stake account belonging to |target|.  Returns success boolean flag.
    fn transfer(&self, msg_sender: B256, destination_address: B256, value: AmountType) -> BoxFuture<bool>;

    /// Transfers |amount_requested| from |source_address|'s stake
    /// account to the stake account belonging to
    /// |destination_address|, when |msg_sender| has a sufficiently
    /// large approval from |source_address|.  Returns success boolean
    /// flag.
    fn transfer_from(&self, msg_sender: B256, source_address: B256,
                     destination_address: B256, value: AmountType) ->
        BoxFuture<bool>;

    /// Approve by |msg_sender| for |spender| to transferFrom up to |value| tokens.
    fn approve(&self, msg_sender: B256, spender_address: B256, value: AmountType) ->
        BoxFuture<bool>;

    fn approve_and_call(&self, msg_sender: B256, spender_address: B256, value: AmountType,
                        extra_data: Vec<u8>) ->
        BoxFuture<bool>;

    fn allowance(&self, owner: B256, spender: B256) -> BoxFuture<AmountType>;

    fn burn(&self, msg_sender: B256, value: AmountType) -> BoxFuture<bool>;

    fn burn_from(&self, msg_sender: B256, owner: B256, value: AmountType) -> BoxFuture<bool>;

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
    fn list_active_escrows_iterator(&self, owner: B256) -> BoxFuture<EscrowAccountIterator>;

    fn list_active_escrows_get(&self, iter: EscrowAccountIterator) ->
        BoxFuture<(EscrowAccountStatus, EscrowAccountIterator)>;

    /// Returns the escrow account data associated with a given |escrow_id|.
    fn fetch_escrow_by_id(&self, escrow_id: EscrowAccountIdType) -> BoxFuture<EscrowAccountStatus>;

    /// Dissolves the escrow account |escrow_id|: the |msg_sender|
    /// must be the target of the escrow account, and
    /// |amount_requested| of the escrow amount is transferred to the
    /// caller's stake account (e.g., stake forfeiture).  Any
    /// remaining amount is marked as available in the stake account
    /// of the creator of the escrow account, i.e., it is released
    /// from escrow and returned back to the owner.  It is an error to
    /// refer to |escrow_id| after this succeeds, since the escrow
    /// account will have been destroyed.
    fn take_and_release_escrow(
        &self,
        msg_sender: B256,
        escrow_id: EscrowAccountIdType,
        amount_requested: AmountType,
    ) -> BoxFuture<AmountType>;
}
