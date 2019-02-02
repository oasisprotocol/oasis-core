extern crate log;

extern crate ekiden_core;
extern crate ekiden_storage_base;
extern crate ekiden_trusted;

extern crate simple_keyvalue_api;

use log::info;

use ekiden_core::error::Result;
use ekiden_trusted::{
    db::database_schema,
    enclave::enclave_init,
    runtime::{create_runtime, dispatcher::RuntimeCallContext},
};
use simple_keyvalue_api::{with_api, KeyValue};

enclave_init!();

// Create enclave runtime interface.
with_api! {
    create_runtime!(api);
}

database_schema! {
    pub struct TestSchema {
        pub some_data: Map<String, String>,
    }
}

pub fn insert(key_value: &KeyValue, _ctx: &RuntimeCallContext) -> Result<Option<String>> {
    info!(
        "Inserting key \"{}\" with associated value\"{}\".",
        key_value.key, key_value.value
    );

    let db = TestSchema::new();

    Ok(db.some_data.insert(&key_value.key, &key_value.value))
}

pub fn get(key: &String, _ctx: &RuntimeCallContext) -> Result<Option<String>> {
    info!("Getting key \"{}\".", key);
    let db = TestSchema::new();

    Ok(db.some_data.get(key))
}

pub fn remove(key: &String, _ctx: &RuntimeCallContext) -> Result<Option<String>> {
    info!("Removing key \"{}\".", key);

    let db = TestSchema::new();
    Ok(db.some_data.remove(key))
}
