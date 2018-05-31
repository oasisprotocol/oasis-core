//! Ekiden dummy stake backend.
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::process::abort;
use std::sync::{Arc, Mutex};

use ekiden_common::bytes::B256;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, BoxFuture};

use ekiden_stake_base::*;

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
    accounts: HashSet<EscrowAccountIdType>,
    // account id, keys for escrow_map below.  \forall a \in accounts:
    // escrow_map[a].owner is stakeholder (key to this instance in
    // stakes below)
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
    id: EscrowAccountIdType,
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
    fn new(id: EscrowAccountIdType, owner: B256, target: B256, amount: AmountType) -> Self {
        Self {
            id: id,
            owner: owner,
            target: target,
            amount: amount,
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
    // Per-entity state.
    stakes: HashMap<B256, DummyStakeEscrowInfo>,
    escrow_map: HashMap<EscrowAccountIdType, EscrowAccount>,

    next_account_id: EscrowAccountIdType,
}

impl DummyStakeEscrowBackendInner {
    pub fn new() -> Self {
        Self {
            stakes: HashMap::new(),
            escrow_map: HashMap::new(),
            next_account_id: EscrowAccountIdType::new(),
        }
    }

    pub fn deposit_stake(
        &mut self,
        msg_sender: B256,
        additional_stake: AmountType, // $$
    ) -> Result<(), Error> {
        let entry = self.stakes
            .entry(msg_sender)
            .or_insert_with(|| DummyStakeEscrowInfo::new());
        if AMOUNT_MAX - entry.amount < additional_stake {
            return Err(Error::new(ErrorCodes::WouldOverflow.to_string()));
        }
        entry.amount += additional_stake;
        Ok(())
    }

    pub fn get_stake_status(&self, msg_sender: B256) -> Result<StakeStatus, Error> {
        match self.stakes.get(&msg_sender) {
            None => Err(Error::new(ErrorCodes::NoStakeAccount.to_string())),
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
            None => Err(Error::new(ErrorCodes::NoStakeAccount.to_string())),
            Some(e) => {
                if e.amount - e.escrowed >= amount_requested {
                    e.amount -= amount_requested;
                    Ok(amount_requested) // $$
                } else {
                    Err(Error::new(ErrorCodes::InsufficientFunds.to_string()))
                }
            }
        }
    }

    pub fn allocate_escrow(
        &mut self,
        msg_sender: B256,
        target: B256,
        escrow_amount: AmountType,
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
                    // 0 <= e.escrowed <= e.amount <= AMOUNT_MAX
                    // e.escrowed + escrow_amount <= AMOUNT_MAX (no overflow)
                    e.escrowed += escrow_amount;
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
                    let entry = EscrowAccount::new(id, msg_sender.clone(), target, escrow_amount);
                    self.escrow_map.insert(id, entry);
                    e.accounts.insert(id);
                    Ok(id)
                }
            }
        }
    }

    pub fn list_active_escrows(&self, msg_sender: B256) -> Result<Vec<EscrowAccount>, Error> {
        let mut results: Vec<EscrowAccount> = Vec::new();
        let a = match self.stakes.get(&msg_sender) {
            None => return Ok(results),
            Some(a) => {
                if a.escrowed == 0 {
                    return Ok(results);
                }
                a
            }
        };

        for ea_id in a.accounts.iter() {
            match self.escrow_map.get(&*ea_id) {
                None => {
                    return Err(Error::new(ErrorCodes::InternalError.to_string()));
                }
                Some(e) => {
                    results.push((*e).clone());
                }
            }
        }

        results.sort();
        Ok(results)
    }

    pub fn fetch_escrow_by_id(
        &self,
        escrow_id: EscrowAccountIdType,
    ) -> Result<EscrowAccount, Error> {
        match self.escrow_map.get(&escrow_id) {
            None => Err(Error::new(ErrorCodes::NoEscrowAccount.to_string())),
            Some(e) => Ok((*e).clone()),
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
            let account = match self.escrow_map.get_mut(&escrow_id) {
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
                if AMOUNT_MAX - target.amount < amount_requested {
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

                stakeholder.amount -= amount_requested;
                stakeholder.escrowed -= account.amount;
                stakeholder.accounts.remove(&escrow_id);
            }
            let target = match self.stakes.get_mut(&msg_sender) {
                None => return Err(Error::new(ErrorCodes::InternalError.to_string())),
                Some(t) => t,
            };
            target.amount += amount_requested;
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
    ) -> BoxFuture<EscrowAccountIdType> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let mut inner = inner.lock().unwrap();
            inner.allocate_escrow(msg_sender, target, escrow_amount)
        }))
    }

    fn list_active_escrows(&self, msg_sender: B256) -> BoxFuture<Vec<EscrowAccountStatus>> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            let mut output = Vec::new();
            let ea_v = match inner.list_active_escrows(msg_sender) {
                Err(e) => return Err(e),
                Ok(v) => v,
            };
            output.extend(
                ea_v.iter()
                    .map(|p| EscrowAccountStatus::new(p.id, p.target, p.amount)),
            );
            Ok(output)
        }))
    }

    fn fetch_escrow_by_id(&self, escrow_id: EscrowAccountIdType) -> BoxFuture<EscrowAccountStatus> {
        let inner = self.inner.clone();
        Box::new(future::lazy(move || {
            let inner = inner.lock().unwrap();
            match inner.fetch_escrow_by_id(escrow_id) {
                Err(e) => return Err(e),
                Ok(ea) => Ok(EscrowAccountStatus::new(ea.id, ea.target, ea.amount)),
            }
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
