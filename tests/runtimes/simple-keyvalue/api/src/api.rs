use serde::{Deserialize, Serialize};

use oasis_core_runtime::runtime_api;

#[derive(Clone, Serialize, Deserialize)]
pub struct Key {
    pub key: String,
    // Nonce is ignored by the runtime itself and can be used to avoid duplicate
    // runtime transactions.
    pub nonce: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyValue {
    pub key: String,
    pub value: String,
    // Nonce is ignored by the runtime itself and can be used to avoid duplicate
    // runtime transactions.
    pub nonce: Option<u64>,
}

runtime_api! {
    //  Gets runtime ID of the runtime.
    pub fn get_runtime_id(()) -> Option<String>;

    // Emit a runtime message.
    pub fn message(u64) -> ();

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
