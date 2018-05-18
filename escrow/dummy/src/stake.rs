//! Ekiden dummy stake backend.
use std::mem::size_of_val;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::process::abort;

use ekiden_common::bytes::B256;
use ekiden_common::entity::Entity;
use ekiden_common::error::Error;
use ekiden_common::futures::{future, BoxFuture, BoxStream};
use ekiden_common::node::Node;
use ekiden_common::signature::Signed;
use ekiden_common::subscribers::StreamSubscribers;
use ekiden_stake_base::*;

struct DummyStakeEscrowInfo {
    owner: Entity,
    amount: u64,  // see max_value() below
    escrowed: u64,
}

struct EscrowAccount<'a> {
    owner: &'a DummyStakeEscrowInfo,
    target: &'a DummyStakeEscrowInfo,
    amount: u64,
}

// We use 32-digits so it can be converted to a B256 easily (do we
// want to use a B256 for escrow account numbers?)  This is also a hot
// spot that prevents simple parallelization by sharding the
// stake/escrow service, since we could simply shard by the
// stakeholder's public key and partition the escrow account numbers
// by the number of shards, or have large blocks of escrow account
// numbers handed out to shards by a central server.

struct LittleEndianCounter32 {
    digits: [u8; 32],
}

impl LittleEndianCounter32 {
    pub fn new() -> Self {
        Self { digits: [0; 32] }
    }

    pub fn inc_mut(&mut self) {
        let mut ix = 0;
        while ix < size_of_val(&self.digits) {
            if { self.digits[ix] += 1; self.digits[ix] != 0 } {
                break;  // no carry needed
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
        LittleEndianCounter32 {
            digits: v.0
        }
    }
}

struct DummyStakeEscrowBackendInner<'a> {
    // Per-entity state.  Use Entity's id field as hash key.
    stakes: HashMap<B256, DummyStakeEscrowInfo>,
    escrow_map: HashMap<B256, EscrowAccount<'a>>,
    // lifetime of EscrowAccount entries cannot exceed that of the
    // StakeEscrowInfo entries inside of the stakes HashMap.

    next_account_id: LittleEndianCounter32,
}

pub struct DummyStakeEscrowBackend<'a> {
    inner: Arc<Mutex<DummyStakeEscrowBackendInner<'a>>>,
    // Do we need to have subscribers? Who needs to know when there
    // might be new escrow accounts created?
}

enum StakeEscrowError {
    WouldOverflow,
}

impl<'a> DummyStakeEscrowBackendInner<'a> {
    pub fn new() -> Self {
        Self {
            stakes: HashMap::new(),
            escrow_map: HashMap::new(),
            next_account_id: LittleEndianCounter32::new(), 
        }
    }

    pub fn desposit_stake(&mut self, user: Entity, additional_stake: u64)
                          -> Result<(), StakeEscrowError> {
        let entry = self.stakes.entry(user.id).or_insert(
            DummyStakeEscrowInfo {
                owner: user.clone(),
                amount: 0,
                escrowed: 0,
            });
        // typeof entry.amount would be nice.
        // if decltype(entry.amount)::max_value() - entry.amount < additional_stake {
        if <u64>::max_value() - entry.amount < additional_stake {
            return Err(StakeEscrowError::WouldOverflow);
        }
        entry.amount += additional_stake;
        Ok(())
    }
}
