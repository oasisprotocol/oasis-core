use oasis_core_runtime::{
    consensus::{registry, staking},
    runtime_api,
};

#[derive(Clone, cbor::Encode, cbor::Decode)]
pub struct Key {
    pub key: String,
    // Nonce is ignored by the runtime itself and can be used to avoid duplicate
    // runtime transactions.
    #[cbor(optional)]
    pub nonce: Option<u64>,
}

#[derive(Clone, cbor::Encode, cbor::Decode)]
pub struct KeyValue {
    pub key: String,
    pub value: String,
    // Nonce is ignored by the runtime itself and can be used to avoid duplicate
    // runtime transactions.
    #[cbor(optional)]
    pub nonce: Option<u64>,
}

#[derive(Clone, cbor::Encode, cbor::Decode)]
pub struct Withdraw {
    pub nonce: u64,
    pub withdraw: staking::Withdraw,
}

#[derive(Clone, cbor::Encode, cbor::Decode)]
pub struct Transfer {
    pub nonce: u64,
    pub transfer: staking::Transfer,
}

#[derive(Clone, cbor::Encode, cbor::Decode)]
pub struct AddEscrow {
    pub nonce: u64,
    pub escrow: staking::Escrow,
}

#[derive(Clone, cbor::Encode, cbor::Decode)]
pub struct ReclaimEscrow {
    pub nonce: u64,
    pub reclaim_escrow: staking::ReclaimEscrow,
}

#[derive(Clone, cbor::Encode, cbor::Decode)]
pub struct UpdateRuntime {
    pub update_runtime: registry::Runtime,
    // Nonce is ignored by the runtime itself and can be used to avoid duplicate
    // runtime transactions.
    #[cbor(optional)]
    pub nonce: Option<u64>,
}

runtime_api! {
    //  Gets runtime ID of the runtime.
    pub fn get_runtime_id(()) -> Option<String>;

    // Does some consensus queries.
    pub fn consensus_accounts(()) -> (BTreeMap<Address, Account>, BTreeMap<Address, BTreeMap<Address, Delegation>>);

    // Withdraw from the consensus layer into the runtime account.
    pub fn consensus_withdraw(Withdraw) -> ();

    // Transfer from the runtime account to another account in the consensus layer.
    pub fn consensus_transfer(Transfer) -> ();

    // Add escrow from the runtime account to an account in the consensus layer.
    pub fn consensus_add_escrow(AddEscrow) -> ();

    // Reclaim escrow to the runtime account.
    pub fn consensus_reclaim_escrow(ReclaimEscrow) -> ();

    // Update existing runtime with given descriptor.
    pub fn update_runtime(UpdateRuntime) -> ();

    // Inserts key and corresponding value and returns old value, if any.
    // Both parameters are passed using a single serializable struct KeyValue.
    pub fn insert(KeyValue) -> Option<String>;

    // Gets value associated with given key.
    pub fn get(Key) -> Option<String>;

    // Removes value associated with the given key and returns old value, if any.
    pub fn remove(Key) -> Option<String>;

    // (encrypted) Inserts key and corresponding value and returns old value, if any.
    // Both parameters are passed using a single serializable struct KeyValue.
    pub fn enc_insert(KeyValue) -> Option<String>;

    // (encrypted) Gets value associated with given key.
    pub fn enc_get(Key) -> Option<String>;

    // (encrypted) Removes value associated with the given key and returns old value, if any.
    pub fn enc_remove(Key) -> Option<String>;
}
