//! Ekiden dummy stake backend.
use std::collections::HashMap;
use std::process::abort;
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::B256;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, BoxFuture};
use ekiden_core::identity::EntityIdentity;

use ekiden_stake_base::*;

// Invariant: 0 <= escrowed <= amount <= AMOUNT_MAX.
struct DummyStakeEscrowInfo {
    amount: AmountType,
    escrowed: AmountType,
    allowances: HashMap<B256, AmountType>,
}

impl DummyStakeEscrowInfo {
    fn new() -> Self {
        Self {
            amount: AmountType::from(0),
            escrowed: AmountType::from(0),
            allowances: HashMap::new(),
        }
    }
}

struct DummyStakeEscrowBackendInner {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: AmountType,

    // Per-address state.
    stakes: HashMap<B256, DummyStakeEscrowInfo>,

    // Hardcoded addresses for the DisputeResolution and EntityRegistry.
    // Only the DisputeResolution can call `take_escrow` and only the
    // EntityRegistry can call `release_escrow`, so we need to have their
    // addresses to check that.
    dispute_resolution_addr: B256,
    entity_registry_addr: B256,
}

// use num::pow instead?
pub fn amount_type_pow(mut base: AmountType, mut exp: u8) -> AmountType {
    let mut result = AmountType::from(1);
    while exp != 0 {
        if exp % 2 != 0 {
            result = result * base;
        }
        base = base * base;
        exp = exp / 2;
    }
    result
}

impl DummyStakeEscrowBackendInner {
    pub fn new(owner_id: B256, name: String, symbol: String, initial_supply: AmountType) -> Self {
        let mut this = Self {
            name: name.clone(),
            symbol: symbol.clone(),
            decimals: 18,
            total_supply: AmountType::from(0),
            stakes: HashMap::new(),
            // These two should be set after initialization with `link_to_...`
            dispute_resolution_addr: B256::from(0),
            entity_registry_addr: B256::from(0),
        };
        {
            let entry = this.stakes
                .entry(owner_id)
                .or_insert_with(|| DummyStakeEscrowInfo::new());
            let scale = amount_type_pow(AmountType::from(10), this.decimals);
            if initial_supply > !AmountType::from(0) / scale {
                println!("Initial token count overflows due to scaling");
                abort();
            }
            let supply = initial_supply * scale;
            entry.amount = supply;
            this.total_supply = supply;
        }
        this
    }

    // Tell the Stake on which address the DisputeResolution was deployed on.
    // This can only be done once.
    pub fn link_to_dispute_resolution(&mut self, dr_addr: B256) -> Result<bool, Error> {
        if self.dispute_resolution_addr != B256::from(0) {
            // Address was already set.
            Err(Error::new(ErrorCodes::AddressAlreadySet.to_string()))
        } else {
            self.dispute_resolution_addr = dr_addr;
            Ok(true)
        }
    }

    // Tell the Stake on which address the EntityRegistry was deployed on.
    // This can only be done once.
    pub fn link_to_entity_registry(&mut self, reg_addr: B256) -> Result<bool, Error> {
        if self.entity_registry_addr != B256::from(0) {
            // Address was already set.
            Err(Error::new(ErrorCodes::AddressAlreadySet.to_string()))
        } else {
            self.entity_registry_addr = reg_addr;
            Ok(true)
        }
    }

    pub fn get_name(&self) -> Result<String, Error> {
        Ok(self.name.clone())
    }

    pub fn get_symbol(&self) -> Result<String, Error> {
        Ok(self.symbol.clone())
    }

    pub fn get_decimals(&self) -> Result<u8, Error> {
        Ok(self.decimals)
    }

    pub fn get_total_supply(&self) -> Result<AmountType, Error> {
        Ok(self.total_supply)
    }

    pub fn get_stake_status(&self, msg_sender: B256) -> Result<StakeStatus, Error> {
        match self.stakes.get(&msg_sender) {
            None => Ok(StakeStatus::new(AmountType::from(0), AmountType::from(0))),
            Some(stake_ref) => Ok(StakeStatus::new(stake_ref.amount, stake_ref.escrowed)),
        }
    }

    pub fn balance_of(&self, owner: B256) -> Result<AmountType, Error> {
        match self.stakes.get(&owner) {
            None => Ok(AmountType::from(0)),
            Some(stake_ref) => Ok(stake_ref.amount - stake_ref.escrowed),
        }
    }

    pub fn transfer(
        &mut self,
        msg_sender: B256,
        destination_address: B256,
        value: AmountType,
    ) -> Result<bool, Error> {
        {
            let entry = match self.stakes.get_mut(&msg_sender) {
                None => return Err(Error::new(ErrorCodes::NoStakeAccount.to_string())),
                Some(e) => e,
            };
            if entry.amount - entry.escrowed < value {
                return Err(Error::new(ErrorCodes::InsufficientFunds.to_string()));
            }
        }
        {
            let target = self.stakes
                .entry(destination_address)
                .or_insert_with(|| DummyStakeEscrowInfo::new());
            if target.amount > !AmountType::from(0) - value {
                return Err(Error::new(ErrorCodes::WouldOverflow.to_string()));
            }
            target.amount = target.amount + value;
        }
        let entry = match self.stakes.get_mut(&msg_sender) {
            None => return Err(Error::new(ErrorCodes::InternalError.to_string())),
            Some(e) => e,
        };
        entry.amount = entry.amount - value;
        Ok(true)
    }

    pub fn transfer_from(
        &mut self,
        msg_sender: B256,
        owner: B256,
        destination_address: B256,
        value: AmountType,
    ) -> Result<bool, Error> {
        let allowed: AmountType;
        {
            let entry = match self.stakes.get_mut(&owner) {
                None => return Err(Error::new(ErrorCodes::NoStakeAccount.to_string())),
                Some(e) => e,
            };
            if entry.amount - entry.escrowed < value {
                return Err(Error::new(ErrorCodes::InsufficientFunds.to_string()));
            }
            allowed = match entry.allowances.get(&msg_sender) {
                None => AmountType::from(0),
                Some(a) => *a,
            };
            if value > allowed {
                return Err(Error::new(ErrorCodes::InsufficientAllowance.to_string()));
            }
        }
        {
            let target = self.stakes
                .entry(destination_address)
                .or_insert_with(|| DummyStakeEscrowInfo::new());
            if target.amount > !AmountType::from(0) - value {
                return Err(Error::new(ErrorCodes::WouldOverflow.to_string()));
            }
            target.amount = target.amount + value;
        }
        let entry = match self.stakes.get_mut(&owner) {
            None => return Err(Error::new(ErrorCodes::InternalError.to_string())),
            Some(e) => e,
        };
        entry.amount = entry.amount - value;
        entry.allowances.insert(msg_sender, allowed - value);
        Ok(true)
    }

    pub fn approve(
        &mut self,
        msg_sender: B256,
        spender_address: B256,
        value: AmountType,
    ) -> Result<bool, Error> {
        // Create an entry if msg_sender does not already have a stakes account...
        let entry = self.stakes
            .entry(msg_sender)
            .or_insert_with(|| DummyStakeEscrowInfo::new());
        // ... since allowances are unchecked wrt available balance,
        // it is okay to over-promise.  The caller _could_ fund the
        // account after the approve invocation.
        entry.allowances.insert(spender_address, value);
        return Ok(true);
    }

    pub fn approve_and_call(
        &mut self,
        msg_sender: B256,
        spender_address: B256,
        value: AmountType,
        _extra_data: Vec<u8>,
    ) -> Result<bool, Error> {
        self.approve(msg_sender, spender_address, value)?;
        // How do we call the spender_address contract?
        //
        // The issue is this: in Solidity, the spender_address is cast
        // to a `tokenRecipient` (see ethereum/contracts/Stake.sol)
        // and the `receiveApproval` function invoked after the
        // approval is done.
        //
        // Here we are implementing Rust interfaces to talk over gRPC
        // to different contract backends, so that a mix of dummy and
        // real Solidity contract implementations can be used.  It is
        // unclear how the cast operation could be done: (1) we need
        // to have a way to look up, via the address, the gRPC
        // endpoint (IP-port); (2) the protobuf request/response
        // encoding would have to be the same (this is probably
        // easiest, by requiring that a standard proto file be used);
        // (3) inject in, without the gRPC auto-generated client stub,
        // the call to the ReceiveApproval gRPC method, if the
        // spender_address also yields the gRPC service endpoint path
        // ("/stake.Stake/ApproveAndCall" in the case of Stake.proto).
        // What about Solidity contracts for which a gRPC interface
        // hasn't been built?
        unimplemented!();
    }

    pub fn allowance(&self, owner: B256, spender: B256) -> Result<AmountType, Error> {
        let entry = match self.stakes.get(&owner) {
            None => return Ok(AmountType::from(0)),
            Some(e) => e,
        };
        let amt = match entry.allowances.get(&spender) {
            None => return Ok(AmountType::from(0)),
            Some(amt) => *amt,
        };
        return Ok(amt);
    }

    pub fn burn(&mut self, msg_sender: B256, value: AmountType) -> Result<bool, Error> {
        let entry = match self.stakes.get_mut(&msg_sender) {
            None => return Err(Error::new(ErrorCodes::NoStakeAccount.to_string())),
            Some(e) => e,
        };
        if value > entry.amount - entry.escrowed {
            return Err(Error::new(ErrorCodes::InsufficientFunds.to_string()));
        }
        entry.amount = entry.amount - value;
        self.total_supply = self.total_supply - value;
        Ok(true)
    }

    pub fn burn_from(
        &mut self,
        msg_sender: B256,
        owner: B256,
        value: AmountType,
    ) -> Result<bool, Error> {
        let entry = match self.stakes.get_mut(&owner) {
            None => return Err(Error::new(ErrorCodes::NoStakeAccount.to_string())),
            Some(e) => e,
        };
        if value > entry.amount - entry.escrowed {
            return Err(Error::new(ErrorCodes::InsufficientFunds.to_string()));
        }
        // Allow burn_from of zero.  In Solidity, if there is no
        // allowance, the mapping object would return 0, and a
        // burn_from of 0 would be considered allowed.
        let allowed = match entry.allowances.get(&msg_sender) {
            None => AmountType::from(0),
            Some(a) => *a,
        };
        if value > allowed {
            return Err(Error::new(ErrorCodes::InsufficientAllowance.to_string()));
        }
        entry.amount = entry.amount - value;
        self.total_supply = self.total_supply - value;
        entry.allowances.insert(msg_sender, allowed - value);
        Ok(true)
    }

    pub fn add_escrow(
        &mut self,
        msg_sender: B256,
        escrow_amount: AmountType,
    ) -> Result<AmountType, Error> {
        // verify if sufficient funds
        match self.stakes.get_mut(&msg_sender) {
            None => Err(Error::new(ErrorCodes::NoStakeAccount.to_string())),
            Some(e) => {
                if e.amount - e.escrowed < escrow_amount {
                    Err(Error::new(ErrorCodes::InsufficientFunds.to_string()))
                } else {
                    // escrow_amount <= e.amount - e.escrowed
                    // ==> e.escrowed + escrow_amount <= e.amount
                    // and since
                    // 0 <= e.escrowed <= e.amount <= !AmountType::from(0)
                    // e.escrowed + escrow_amount <= !AmountType::from(0) (no overflow)
                    e.escrowed = e.escrowed + escrow_amount;
                    Ok(e.escrowed)
                }
            }
        }
    }

    pub fn fetch_escrow_amount(&self, owner: B256) -> Result<AmountType, Error> {
        match self.stakes.get(&owner) {
            None => Err(Error::new(ErrorCodes::NoStakeAccount.to_string())),
            Some(e) => Ok(e.escrowed),
        }
    }

    pub fn take_escrow(
        &mut self,
        msg_sender: B256,
        owner: B256,
        amount_requested: AmountType,
    ) -> Result<AmountType, Error> {
        // Only the DisputeResolution may take escrow!
        if msg_sender != self.dispute_resolution_addr {
            return Err(Error::new(ErrorCodes::InternalError.to_string()));
        }

        {
            // amount_requested is credited to the target
            // account. First ensure that no overflow can occur.
            let target = self.stakes
                .entry(msg_sender)
                .or_insert_with(|| DummyStakeEscrowInfo::new());
            if !AmountType::from(0) - target.amount < amount_requested {
                return Err(Error::new(ErrorCodes::WouldOverflow.to_string()));
            }
        }

        {
            let account = match self.stakes.get_mut(&owner) {
                None => return Err(Error::new(ErrorCodes::NoStakeAccount.to_string())),
                Some(stake_account) => stake_account,
            };
            if amount_requested > account.escrowed {
                return Err(Error::new(
                    ErrorCodes::RequestExceedsEscrowedFunds.to_string(),
                ));
            };
            // post: amount_requested <= account.escrowed
            {
                // check some invariants:
                //
                // total tied up in escrow cannot exceed stake
                if account.amount < account.escrowed {
                    return Err(Error::new(ErrorCodes::InternalError.to_string()));
                }

                account.amount = account.amount - amount_requested;
                account.escrowed = account.escrowed - amount_requested;
            }
        }

        {
            let target = match self.stakes.get_mut(&msg_sender) {
                None => return Err(Error::new(ErrorCodes::InternalError.to_string())),
                Some(t) => t,
            };
            target.amount = target.amount + amount_requested;
        }

        // amount_available'
        //   = stakeholder.amount' - stakeholder.escrowed'
        //   = stakeholder.amount - amount_requested - (stakeholder.escrowed - account.escrowed)
        //   = stakeholder.amount - stakeholder.escrowed + (account.escrowed - amount_requested)
        //   = amount_avaiable + (account.escrowed - amount_requested)
        // stakeholder.escrowed'
        //   = stakeholder.escrowed - account.escrowed.
        // ∴ invariants maintained.

        Ok(amount_requested) // $$
    }

    fn release_escrow(&mut self, msg_sender: B256, owner: B256) -> Result<AmountType, Error> {
        // Only the EntityRegistry may release escrow!
        if msg_sender != self.entity_registry_addr {
            return Err(Error::new(ErrorCodes::InternalError.to_string()));
        }

        let account = match self.stakes.get_mut(&owner) {
            None => return Err(Error::new(ErrorCodes::NoStakeAccount.to_string())),
            Some(stake_account) => stake_account,
        };

        // Check invariants.
        if account.amount < account.escrowed {
            return Err(Error::new(ErrorCodes::InternalError.to_string()));
        }

        // Release the remainder of the escrow to the owner.
        let amount_returned = account.escrowed;
        account.escrowed = AmountType::from(0);
        Ok(amount_returned)
    }
}

pub struct DummyStakeEscrowBackend {
    inner: Arc<Mutex<DummyStakeEscrowBackendInner>>,
    // Do we need to have subscribers? Who needs to know when there
    // might be new escrow added?
}

impl DummyStakeEscrowBackend {
    pub fn new(owner_id: B256, name: String, symbol: String, initial_supply: AmountType) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DummyStakeEscrowBackendInner::new(
                owner_id,
                name,
                symbol,
                initial_supply,
            ))),
        }
    }
}

impl StakeEscrowBackend for DummyStakeEscrowBackend {
    fn link_to_dispute_resolution(&self, address: B256) -> BoxFuture<bool> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();
            inner.link_to_dispute_resolution(address)
        }))
    }

    fn link_to_entity_registry(&self, address: B256) -> BoxFuture<bool> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();
            inner.link_to_entity_registry(address)
        }))
    }

    fn get_name(&self) -> BoxFuture<String> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            inner.get_name()
        }))
    }

    fn get_symbol(&self) -> BoxFuture<String> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            inner.get_symbol()
        }))
    }

    fn get_decimals(&self) -> BoxFuture<u8> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            inner.get_decimals()
        }))
    }

    fn get_total_supply(&self) -> BoxFuture<AmountType> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            inner.get_total_supply()
        }))
    }

    fn get_stake_status(&self, owner: B256) -> BoxFuture<StakeStatus> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            inner.get_stake_status(owner)
        }))
    }

    fn balance_of(&self, owner: B256) -> BoxFuture<AmountType> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            inner.balance_of(owner)
        }))
    }

    fn transfer(
        &self,
        msg_sender: B256,
        destination_address: B256,
        value: AmountType,
    ) -> BoxFuture<bool> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();
            inner.transfer(msg_sender, destination_address, value)
        }))
    }

    fn transfer_from(
        &self,
        msg_sender: B256,
        source_address: B256,
        destination_address: B256,
        value: AmountType,
    ) -> BoxFuture<bool> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();
            inner.transfer_from(msg_sender, source_address, destination_address, value)
        }))
    }

    fn approve(&self, msg_sender: B256, spender: B256, value: AmountType) -> BoxFuture<bool> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();
            inner.approve(msg_sender, spender, value)
        }))
    }

    fn approve_and_call(
        &self,
        msg_sender: B256,
        spender: B256,
        value: AmountType,
        extra_data: Vec<u8>,
    ) -> BoxFuture<bool> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();
            inner.approve_and_call(msg_sender, spender, value, extra_data)
        }))
    }

    fn allowance(&self, owner: B256, spender: B256) -> BoxFuture<AmountType> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            inner.allowance(owner, spender)
        }))
    }

    fn burn(&self, msg_sender: B256, value: AmountType) -> BoxFuture<bool> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();
            inner.burn(msg_sender, value)
        }))
    }

    fn burn_from(&self, msg_sender: B256, owner: B256, value: AmountType) -> BoxFuture<bool> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();
            inner.burn_from(msg_sender, owner, value)
        }))
    }

    fn add_escrow(&self, msg_sender: B256, escrow_amount: AmountType) -> BoxFuture<AmountType> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();
            inner.add_escrow(msg_sender, escrow_amount)
        }))
    }

    fn fetch_escrow_amount(&self, owner: B256) -> BoxFuture<AmountType> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            inner.fetch_escrow_amount(owner)
        }))
    }

    fn take_escrow(
        &self,
        msg_sender: B256,
        owner: B256,
        amount_requested: AmountType,
    ) -> BoxFuture<AmountType> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();
            inner.take_escrow(msg_sender, owner, amount_requested)
        }))
    }

    fn release_escrow(&self, msg_sender: B256, owner: B256) -> BoxFuture<AmountType> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();
            inner.release_escrow(msg_sender, owner)
        }))
    }
}

// Register for dependency injection.
create_component!(
    dummy,
    "stake-backend",
    DummyStakeEscrowBackend,
    StakeEscrowBackend,
    (|container: &mut Container| -> Result<Box<Any>> {
        let entity_identity = container.inject::<EntityIdentity>()?;
        let owner_id = entity_identity.get_public_key();
        let instance: Box<StakeEscrowBackend> = Box::new(DummyStakeEscrowBackend::new(
            owner_id,
            "Oasis Stake".to_string(),
            "OS$".to_string(),
            AmountType::from(100_000_000),
        ));
        Ok(Box::new(instance))
    }),
    []
);
