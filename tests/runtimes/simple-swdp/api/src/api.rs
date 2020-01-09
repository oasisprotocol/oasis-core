use serde_derive::{Deserialize, Serialize};

use oasis_core_runtime::runtime_api;

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyValue {
    pub key: String,
    pub value: String,
}

runtime_api! {
    // Inserts key and corresponding value and returns old value, if any.
    // Both parameters are passed using a single serializable struct KeyValue.
    pub fn insert(KeyValue) -> Option<String>;

    // Gets value associated with given key.
    pub fn get(String) -> Option<String>;

    // Removes value associated with the given key and returns old value, if any.
    pub fn remove(String) -> Option<String>;

    // (encrypted) Inserts key and corresponding value and returns old value, if any.
    // Both parameters are passed using a single serializable struct KeyValue.
    pub fn enc_insert(KeyValue) -> Option<String>;

    // (encrypted) Gets value associated with given key.
    pub fn enc_get(String) -> Option<String>;

    // (encrypted) Removes value associated with the given key and returns old value, if any.
    pub fn enc_remove(String) -> Option<String>;
}
