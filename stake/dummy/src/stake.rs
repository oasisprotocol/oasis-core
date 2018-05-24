//! Ekiden dummy stake backend.
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::mem::size_of_val;
use std::process::abort;
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::B256;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, BoxFuture};

use ekiden_stake_api as api;
use ekiden_stake_base::*;

// We put all error strings from which we construct Error::new(...)
// here, so that we should not have a typographical error (e.g., "No
// Account") in one of several error paths, leading to error handlers
// that try to do string comparisons misfiring.  Ideally we could have
// per-module enums or something like that, and have the errors
// propagate through gRPC...

pub static INTERNAL_ERROR: &str = "INTERNAL ERROR: Invariance violation";
pub static NO_STAKE_ACCOUNT: &str = "No such stake account";
pub static NO_ESCROW_ACCOUNT: &str = "No such escrow account";
pub static WOULD_OVERFLOW: &str = "Would overflow";
pub static INSUFFICIENT_FUNDS: &str = "Insufficient funds";
pub static REQUEST_EXCEEDS_ESCROWED: &str = "Request exceeds escrowed funds";

// It would be nice if DummyStakeEscrowInfo contained its owner ID so
// that EscrowAccount's owner and target can be just a reference to
// the appropriate DummyStakeEscrowInfo.  The dynamic lifetime,
// however, is not something that Rust's lifetime annotation can
// handle, and would require the use of Rc or Arc to essentially share
// ownership.  For now, we just store keys rather than references.

// Invariant: 0 <= escrowed <= amount <= AMOUNT_MAX.
struct DummyStakeEscrowInfo {
    amount: AmountType,   // see max_value() below
    escrowed: AmountType, // sum_{a \in accounts} escrow_map[a].amount
    accounts: HashSet<B256>, // account id, keys for escrow_map below
                          // \forall a \in accounts: escrow_map[a].owner is stakeholder (key
                          // to this instance in stakes below)
}

impl DummyStakeEscrowInfo {
    fn new() -> Self {
        Self {
            amount: 0,
            escrowed: 0,
            accounts: HashSet::new(),
        }
    }
}

#[derive(Clone, Eq)]
struct EscrowAccount {
    id: B256,
    owner: B256,  // &DummyStakeEscrowInfo
    target: B256, // &DummyStakeEscrowInfo
    amount: AmountType,
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
                    Ordering::Equal => self.amount.cmp(&other.amount),
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
    fn new(id: B256, owner: B256, target: B256, amount: AmountType) -> Self {
        Self {
            id: id,
            owner: owner,
            target: target,
            amount: amount,
        }
    }
}

// We use 32-bytes / 64 hex digits so it can be converted to a B256
// easily (do we want to use a B256 for escrow account numbers?)
// Using a counter, however, creates a contention hot spot that
// prevents simple parallelization by sharding the stake/escrow
// service, since we could otherwise simply dispatch to shards by the
// stakeholder's public key and partition the escrow account numbers
// by the number of shards, or have large blocks of escrow account
// numbers handed out to shards by a central server.

pub struct LittleEndianCounter32 {
    digits: [u8; 32],
}

impl LittleEndianCounter32 {
    pub fn new() -> Self {
        Self { digits: [0; 32] }
    }

    pub fn incr_mut(&mut self) {
        let mut ix = 0;
        while ix < size_of_val(&self.digits) {
            if {
                self.digits[ix] += 1;
                self.digits[ix] != 0
            } {
                break; // no carry needed
            }
            ix += 1;
        }
        if ix == size_of_val(&self.digits) {
            println!("There were a lot more than nine billion names, but I'm done!");
            abort()
        }
    }

    pub fn to_b256(&self) -> B256 {
        B256::from(self.digits.clone())
    }

    pub fn from_b256(v: B256) -> LittleEndianCounter32 {
        // Is there a better way to do this?  It seems like
        // digit-based member field access is for non-public
        // interfaces and named member or getters/setters etc would be
        // public interfaces.  Should we just serialize the B256 into
        // digits?  The serde Serializer interface seems huge and
        // might be overkill.
        LittleEndianCounter32 { digits: v.0 }
    }
}

struct DummyStakeEscrowBackendInner {
    // Per-entity state.
    stakes: HashMap<B256, DummyStakeEscrowInfo>,
    escrow_map: HashMap<B256, EscrowAccount>,

    next_account_id: LittleEndianCounter32,
}

impl DummyStakeEscrowBackendInner {
    pub fn new() -> Self {
        Self {
            stakes: HashMap::new(),
            escrow_map: HashMap::new(),
            next_account_id: LittleEndianCounter32::new(),
        }
    }

    pub fn deposit_stake(
        &mut self,
        msg_sender: B256,
        additional_stake: AmountType,
    ) -> Result<(), Error> {
        let entry = self.stakes
            .entry(msg_sender)
            .or_insert_with(|| DummyStakeEscrowInfo::new());
        if AMOUNT_MAX - entry.amount < additional_stake {
            return Err(Error::new(WOULD_OVERFLOW));
        }
        entry.amount += additional_stake;
        Ok(())
    }

    pub fn get_stake_status(&self, msg_sender: B256) -> Result<StakeStatus, Error> {
        match self.stakes.get(&msg_sender) {
            None => Err(Error::new(NO_STAKE_ACCOUNT)),
            Some(stake_ref) => Ok(StakeStatus {
                total_stake: stake_ref.amount,
                escrowed: stake_ref.escrowed,
            }),
        }
    }

    pub fn withdraw_stake(
        &mut self,
        msg_sender: B256,
        amount_requested: AmountType,
    ) -> Result<AmountType, Error> {
        match self.stakes.get_mut(&msg_sender) {
            None => Err(Error::new(NO_STAKE_ACCOUNT)),
            Some(e) => {
                if e.amount - e.escrowed >= amount_requested {
                    e.amount -= amount_requested;
                    Ok(amount_requested)
                } else {
                    Err(Error::new(INSUFFICIENT_FUNDS))
                }
            }
        }
    }

    pub fn allocate_escrow(
        &mut self,
        msg_sender: B256,
        target: B256,
        escrow_amount: AmountType,
    ) -> Result<B256, Error> {
        // verify if sufficient funds
        match self.stakes.get_mut(&msg_sender) {
            None => Err(Error::new(NO_STAKE_ACCOUNT)),
            Some(e) => {
                if e.amount - e.escrowed < escrow_amount {
                    Err(Error::new(INSUFFICIENT_FUNDS))
                } else {
                    // escrow_amount <= e.amount - e.escrowed
                    // ==> e.escrowed + escrow_amount <= e.amount
                    // and since
                    // 0 <= e.escrowed <= e.amount <= AMOUNT_MAX
                    // e.escrowed + escrow_amount <= AMOUNT_MAX (no overflow)
                    e.escrowed += escrow_amount;
                    let id = self.next_account_id.to_b256();
                    let entry =
                        EscrowAccount::new(id.clone(), msg_sender.clone(), target, escrow_amount);
                    self.escrow_map.insert(id.clone(), entry);
                    e.accounts.insert(id.clone());
                    self.next_account_id.incr_mut();
                    Ok(id)
                }
            }
        }
    }

    pub fn list_active_escrows(&self, msg_sender: B256) -> Result<Vec<EscrowAccount>, Error> {
        let mut results: Vec<EscrowAccount> = Vec::new();
        match self.stakes.get(&msg_sender) {
            None => Ok(results),
            Some(a) => {
                if a.escrowed == 0 {
                    return Ok(results);
                }

                for ea_id in a.accounts.iter() {
                    match self.escrow_map.get(&*ea_id) {
                        None => {
                            return Err(Error::new(INTERNAL_ERROR));
                        }
                        Some(e) => {
                            results.push((*e).clone());
                        }
                    }
                }

                results.sort();
                Ok(results)
            }
        }
    }

    pub fn fetch_escrow_by_id(&self, escrow_id: B256) -> Result<EscrowAccount, Error> {
        match self.escrow_map.get(&escrow_id) {
            None => Err(Error::new(NO_ESCROW_ACCOUNT)),
            Some(e) => Ok((*e).clone()),
        }
    }

    pub fn take_and_release_escrow(
        &mut self,
        msg_sender: B256,
        escrow_id: B256,
        amount_requested: AmountType,
    ) -> Result<AmountType, Error> {
        let info = match self.stakes.get_mut(&msg_sender) {
            None => return Err(Error::new(NO_STAKE_ACCOUNT)),
            Some(stake_info) => stake_info,
        };
        {
            let account = match self.escrow_map.get_mut(&escrow_id) {
                None => return Err(Error::new(NO_ESCROW_ACCOUNT)),
                Some(escrow_account) => escrow_account,
            };
            if !(info.accounts.contains(&escrow_id)) {
                return Err(Error::new(INTERNAL_ERROR));
            }
            if amount_requested > account.amount {
                return Err(Error::new(REQUEST_EXCEEDS_ESCROWED));
            };
            // post: amount_requested <= account.amount

            // check some invariants
            if !(account.amount <= info.escrowed) {
                return Err(Error::new(INTERNAL_ERROR));
            }
            // single escrow account value cannot exceed total escrowed
            if !(info.escrowed <= info.amount) {
                return Err(Error::new(INTERNAL_ERROR));
            }
            // total tied up in escrow cannot exceed stake

            info.amount -= amount_requested;
            info.escrowed -= account.amount;
            info.accounts.remove(&escrow_id);
        } // terminate self.escrow_map mutable borrow via `account`
        self.escrow_map.remove(&escrow_id);
        // amount_available' = info.amount' - info.escrowed'
        //                   = info.amount - amount_requested - (info.escrowed - account.amount)
        //                   = info.amount - info.escrowed + (account.amount - amount_requested)
        //                   = amount_avaiable + (account.amount - amount_requested)
        // info.escrowed' = info.escrowed - account.amount.
        //                = \sum_{a \in info.accounts} escrow_map[a].amount - account.amount
        //                = \sum_{a \in info.accounts'} escrow_map[a].amount
        // ∴ invariants maintained.

        Ok(amount_requested)
    }
}

pub struct DummyStakeEscrowBackend {
    inner: Arc<Mutex<DummyStakeEscrowBackendInner>>,
    // Do we need to have subscribers? Who needs to know when there
    // might be new escrow accounts created?
}

impl DummyStakeEscrowBackend {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(DummyStakeEscrowBackendInner::new())),
        }
    }
}

impl StakeEscrowBackend for DummyStakeEscrowBackend {
    fn deposit_stake(&self, msg_sender: B256, amount: AmountType) -> BoxFuture<()> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();
            inner.deposit_stake(msg_sender, amount)
        }))
    }

    fn get_stake_status(&self, msg_sender: B256) -> BoxFuture<StakeStatus> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            inner.get_stake_status(msg_sender)
        }))
    }

    fn withdraw_stake(
        &self,
        msg_sender: B256,
        amount_requested: AmountType,
    ) -> BoxFuture<AmountType> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();
            inner.withdraw_stake(msg_sender, amount_requested)
        }))
    }

    fn allocate_escrow(
        &self,
        msg_sender: B256,
        target: B256,
        escrow_amount: AmountType,
    ) -> BoxFuture<B256> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();
            inner.allocate_escrow(msg_sender, target, escrow_amount)
        }))
    }

    fn list_active_escrows(&self, msg_sender: B256) -> BoxFuture<Vec<api::EscrowData>> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            let mut output = Vec::new();
            let ea_v = match inner.list_active_escrows(msg_sender) {
                Err(e) => return Err(e),
                Ok(v) => v,
            };
            output.extend(ea_v.iter().map(|p| {
                let mut api_ed = api::EscrowData::new();
                api_ed.set_escrow_id(p.id.to_vec());
                api_ed.set_entity(p.target.to_vec());
                api_ed.set_amount(p.amount);
                api_ed
            }));
            Ok(output)
        }))
    }

    fn fetch_escrow_by_id(&self, escrow_id: B256) -> BoxFuture<api::EscrowData> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            let escrow_account = match inner.fetch_escrow_by_id(escrow_id) {
                Err(e) => {
                    return Err(e);
                }
                Ok(ea) => ea,
            };
            let mut ed: api::EscrowData = api::EscrowData::new();
            ed.set_escrow_id(escrow_account.id.to_vec());
            ed.set_entity(escrow_account.target.to_vec());
            ed.set_amount(escrow_account.amount);
            Ok(ed)
        }))
    }

    fn take_and_release_escrow(
        &self,
        msg_sender: B256,
        escrow_id: B256,
        amount_requested: AmountType,
    ) -> BoxFuture<AmountType> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();
            inner.take_and_release_escrow(msg_sender, escrow_id, amount_requested)
        }))
    }
}
