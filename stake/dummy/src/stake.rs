//! Ekiden dummy stake backend.
use std::cmp::Ordering;
use std::collections::HashMap;
use std::process::abort;
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::B256;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, BoxFuture};
use ekiden_common::usize_iterable_hashset::UsizeIterableHashSet;
use ekiden_core::identity::EntityIdentity;

use ekiden_stake_base::*;

// To implement the iterators which contain state in an opaque B256
// state value, we could stuff the HashSet's .iter() into the B256,
// but that would be unsafe since the peer could modify the state
// before using the iterator.  Instead, we implement
// UsizeIterableHashSet so that the iterator state is just a usize
// value; it is invalidated by operations on the HashSet, but bogus
// values are not dangerous.  We could also have kept a hashmap from
// tokens to iterators and encode the tokens in the B256 values, but
// then abandoned iterators would leak memory.

// It would be nice if DummyStakeEscrowInfo contained its owner ID so
// that EscrowAccount's owner and target can be just a reference to
// the appropriate DummyStakeEscrowInfo.  The dynamic lifetime,
// however, is not something that Rust's lifetime annotation can
// handle, and would require the use of Rc or Arc to essentially share
// ownership.  For now, we just store keys rather than references.

// Invariant: 0 <= escrowed <= amount <= AMOUNT_MAX.
struct DummyStakeEscrowInfo {
    amount: AmountType,
    escrowed: AmountType, // sum_{a \in accounts} escrow_map[a].amount
    accounts: UsizeIterableHashSet<EscrowAccountIdType>,
    // account id, keys for escrow_map below.  \forall a \in accounts:
    // escrow_map[a].owner is stakeholder (key to this instance in
    // stakes below)
    allowances: HashMap<B256, AmountType>,
}

impl DummyStakeEscrowInfo {
    fn new() -> Self {
        Self {
            amount: AmountType::from(0),
            escrowed: AmountType::from(0),
            // accounts: HashSet::new(),
            accounts: UsizeIterableHashSet::new(),
            allowances: HashMap::new(),
        }
    }
}

#[derive(Clone, Eq)]
struct EscrowAccount {
    id: EscrowAccountIdType,
    owner: B256,  // &DummyStakeEscrowInfo
    target: B256, // &DummyStakeEscrowInfo
    amount: AmountType,
    aux: B256,
}

impl Ord for EscrowAccount {
    fn cmp(&self, other: &EscrowAccount) -> Ordering {
        match self.id.cmp(&other.id) {
            Ordering::Less => Ordering::Less,
            Ordering::Greater => Ordering::Greater,
            Ordering::Equal => match self.owner.cmp(&other.owner) {
                Ordering::Less => Ordering::Less,
                Ordering::Greater => Ordering::Greater,
                Ordering::Equal => match self.target.cmp(&other.target) {
                    Ordering::Less => Ordering::Less,
                    Ordering::Greater => Ordering::Greater,
                    Ordering::Equal => match self.amount.cmp(&other.amount) {
                        Ordering::Less => Ordering::Less,
                        Ordering::Greater => Ordering::Greater,
                        Ordering::Equal => self.aux.cmp(&other.aux),
                        // There should never be 2 accounts equal
                        // except for aux.  Actually, id should be
                        // unique, so all except for the id.cmp should
                        // be code that never executes.
                    },
                },
            },
        }
    }
}

impl PartialOrd for EscrowAccount {
    fn partial_cmp(&self, other: &EscrowAccount) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for EscrowAccount {
    fn eq(&self, other: &EscrowAccount) -> bool {
        self.id == other.id && self.owner == other.owner && self.target == other.target
            && self.amount == other.amount
    }
}

impl EscrowAccount {
    fn new(
        id: EscrowAccountIdType,
        owner: B256,
        target: B256,
        amount: AmountType,
        aux: B256,
    ) -> Self {
        Self {
            id: id,
            owner: owner,
            target: target,
            amount: amount,
            aux: aux,
        }
    }
}

// We use a B256 as a counter for escrow account numbers.  This is
// deterministic.  However, it creates a contention hot spot that
// prevents simple parallelization by sharding the stake/escrow
// service, since we could otherwise simply dispatch to shards by the
// stakeholder's public key and partition the escrow account numbers
// by the number of shards, or have large blocks of escrow account
// numbers handed out to shards by a central server.

struct DummyStakeEscrowBackendInner {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: AmountType,

    // Per-address state.
    stakes: HashMap<B256, DummyStakeEscrowInfo>,
    escrow_map: HashMap<EscrowAccountIdType, EscrowAccount>,

    next_account_id: EscrowAccountIdType,
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

// usize is 0..2^32-1 or 0..2^64-1; big endian since bytes.rs From<u64> is big endian
fn b256_to_usize(x: B256) -> usize {
    let mut v: usize = 0;
    let bytes = x.to_vec();
    let nbytes;
    if usize::max_value() == u64::max_value() as usize
        && usize::max_value() as u64 == u64::max_value()
    {
        nbytes = 8;
    } else {
        nbytes = 4;
    }
    let vbytes = bytes.len();
    for ix in vbytes - nbytes..vbytes {
        v = v << 8;
        v |= bytes[ix] as usize;
    }
    v
}

impl DummyStakeEscrowBackendInner {
    pub fn new(owner_id: B256, name: String, symbol: String, initial_supply: AmountType) -> Self {
        let mut this = Self {
            name: name.clone(),
            symbol: symbol.clone(),
            decimals: 18,
            total_supply: AmountType::from(0),
            stakes: HashMap::new(),
            escrow_map: HashMap::new(),
            next_account_id: EscrowAccountIdType::new(),
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

    pub fn allocate_escrow(
        &mut self,
        msg_sender: B256,
        target: B256,
        escrow_amount: AmountType,
        aux: B256,
    ) -> Result<EscrowAccountIdType, Error> {
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
                    let id = self.next_account_id;
                    match self.next_account_id.incr_mut() {
                        Err(_e) => {
                            println!(
                                "There were a lot more than nine billion names, but I'm done!"
                            );
                            abort()
                        }
                        Ok(()) => (),
                    }
                    let entry =
                        EscrowAccount::new(id, msg_sender.clone(), target, escrow_amount, aux);
                    self.escrow_map.insert(id, entry);
                    e.accounts.insert(id);
                    Ok(id)
                }
            }
        }
    }

    pub fn list_active_escrows_iterator(
        &self,
        owner: B256,
    ) -> Result<EscrowAccountIterator, Error> {
        match self.stakes.get(&owner) {
            None => return Ok(EscrowAccountIterator::new(false, owner, B256::zero())),
            Some(_e) => return Ok(EscrowAccountIterator::new(true, owner, B256::zero())),
        }
    }

    pub fn list_active_escrows_get(
        &self,
        iter: EscrowAccountIterator,
    ) -> Result<(EscrowAccountStatus, EscrowAccountIterator), Error> {
        let owner = iter.owner;
        let entry = match self.stakes.get(&owner) {
            None => return Err(Error::new(ErrorCodes::NoStakeAccount.to_string())),
            Some(e) => e,
        };
        let mut ix = b256_to_usize(iter.state);
        if ix >= entry.accounts.len() {
            return Err(Error::new(ErrorCodes::InvalidIterator.to_string()));
        }
        let id = match entry.accounts.iter_get(ix) {
            None => return Err(Error::new(ErrorCodes::InvalidIterator.to_string())),
            Some(id) => id,
        };
        let account = match self.escrow_map.get(id) {
            None => return Err(Error::new(ErrorCodes::InvalidIterator.to_string())),
            Some(act) => act,
        };
        let status =
            EscrowAccountStatus::new(account.id, account.target, account.amount, account.aux);
        ix = ix + 1;
        let has_next = ix < entry.accounts.len();
        let new_it = EscrowAccountIterator::new(has_next, owner, B256::from(ix as u64));
        Ok((status, new_it))
    }

    pub fn fetch_escrow_by_id(
        &self,
        escrow_id: EscrowAccountIdType,
    ) -> Result<EscrowAccountStatus, Error> {
        match self.escrow_map.get(&escrow_id) {
            None => Err(Error::new(ErrorCodes::NoEscrowAccount.to_string())),
            Some(e) => Ok(EscrowAccountStatus::new(e.id, e.target, e.amount, e.aux)),
        }
    }

    // |msg_sender| must be the target of the escrow account identified by |escrow_id|.
    // The escrow account is destroyed and funds dispersed if this call succeeds.
    // Note that the amount claimed by the target is transferred out in the return,
    // rather than transferred over to the msg_sender's stake account.
    pub fn take_and_release_escrow(
        &mut self,
        msg_sender: B256,
        escrow_id: EscrowAccountIdType,
        amount_requested: AmountType,
    ) -> Result<AmountType, Error> {
        // msg_sender is the target of the escrow

        {
            let account = match self.escrow_map.get(&escrow_id) {
                None => return Err(Error::new(ErrorCodes::NoEscrowAccount.to_string())),
                Some(escrow_account) => escrow_account,
            };
            if amount_requested > account.amount {
                return Err(Error::new(
                    ErrorCodes::RequestExceedsEscrowedFunds.to_string(),
                ));
            };
            if account.target != msg_sender {
                return Err(Error::new(ErrorCodes::CallerNotEscrowTarget.to_string()));
            }
            // post: amount_requested <= account.amount

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
                let stakeholder = match self.stakes.get_mut(&account.owner) {
                    None => return Err(Error::new(ErrorCodes::InternalError.to_string())),
                    Some(sh) => sh,
                };
                if !(stakeholder.accounts.contains(&escrow_id)) {
                    return Err(Error::new(ErrorCodes::InternalError.to_string()));
                }

                // check some invariants:
                //
                // total tied up in escrow cannot exceed stake
                if stakeholder.amount < stakeholder.escrowed {
                    return Err(Error::new(ErrorCodes::InternalError.to_string()));
                }
                // single escrow account value cannot exceed total escrowed
                if stakeholder.escrowed < account.amount {
                    return Err(Error::new(ErrorCodes::InternalError.to_string()));
                }

                stakeholder.amount = stakeholder.amount - amount_requested;
                stakeholder.escrowed = stakeholder.escrowed - account.amount;
                stakeholder.accounts.remove(&escrow_id);
            }
            let target = match self.stakes.get_mut(&msg_sender) {
                None => return Err(Error::new(ErrorCodes::InternalError.to_string())),
                Some(t) => t,
            };
            target.amount = target.amount + amount_requested;
        } // terminate self.escrow_map mutable borrow via `account`
        self.escrow_map.remove(&escrow_id);
        // amount_available'
        //   = stakeholder.amount' - stakeholder.escrowed'
        //   = stakeholder.amount - amount_requested - (stakeholder.escrowed - account.amount)
        //   = stakeholder.amount - stakeholder.escrowed + (account.amount - amount_requested)
        //   = amount_avaiable + (account.amount - amount_requested)
        // stakeholder.escrowed'
        //   = stakeholder.escrowed - account.amount.
        //   = \sum_{a \in stakeholder.accounts} escrow_map[a].amount - account.amount
        //   = \sum_{a \in stakeholder.accounts'} escrow_map[a].amount
        // ∴ invariants maintained.

        Ok(amount_requested) // $$
    }
}

pub struct DummyStakeEscrowBackend {
    inner: Arc<Mutex<DummyStakeEscrowBackendInner>>,
    // Do we need to have subscribers? Who needs to know when there
    // might be new escrow accounts created?
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

    fn allocate_escrow(
        &self,
        msg_sender: B256,
        target: B256,
        escrow_amount: AmountType,
        aux: B256,
    ) -> BoxFuture<EscrowAccountIdType> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();
            inner.allocate_escrow(msg_sender, target, escrow_amount, aux)
        }))
    }

    fn list_active_escrows_iterator(&self, owner: B256) -> BoxFuture<EscrowAccountIterator> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            inner.list_active_escrows_iterator(owner)
        }))
    }

    fn list_active_escrows_get(
        &self,
        iter: EscrowAccountIterator,
    ) -> BoxFuture<(EscrowAccountStatus, EscrowAccountIterator)> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            inner.list_active_escrows_get(iter)
        }))
    }

    fn fetch_escrow_by_id(&self, escrow_id: EscrowAccountIdType) -> BoxFuture<EscrowAccountStatus> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            inner.fetch_escrow_by_id(escrow_id)
        }))
    }

    fn take_and_release_escrow(
        &self,
        msg_sender: B256,
        escrow_id: EscrowAccountIdType,
        amount_requested: AmountType,
    ) -> BoxFuture<AmountType> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();
            inner.take_and_release_escrow(msg_sender, escrow_id, amount_requested)
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
