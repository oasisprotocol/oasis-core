#[macro_use]
extern crate clap;

extern crate ekiden_core;
extern crate ekiden_rpc_client;
#[macro_use]
extern crate ekiden_runtime_client;
extern crate log;

extern crate serde_json;
extern crate simple_keyvalue_api;

use clap::{App, Arg};
use log::info;

use ekiden_core::tokio;
use ekiden_runtime_client::create_runtime_client;
use simple_keyvalue_api::{with_api, KeyValue};

with_api! {
    create_runtime_client!(simple_keyvalue, simple_keyvalue_api, api);
}

fn main() {
    info!("Initializing simple key/value runtime!");
    let client = runtime_client!(simple_keyvalue);
    let mut runtime = tokio::runtime::Runtime::new().unwrap();

    let kv = KeyValue {
        key: String::from("hello_key"),
        value: String::from("hello_value"),
    };
    info!(
        "Storing \"{}\" as key and \"{}\" as value to database...",
        kv.key, kv.value
    );
    let r = runtime.block_on(client.insert(kv)).unwrap();
    assert_eq!(r, None); // key should not exist in db before

    info!("Getting \"hello_key\"...");
    let r = runtime
        .block_on(client.get("hello_key".to_string()))
        .unwrap();
    match r {
        Some(val) => {
            info!("Got \"{}\"", val);
            assert_eq!(val, "hello_value")
        } // key should exist in db
        None => {
            info!("Key not found");
            panic!("Key \"hello_value\" not found, but it should.")
        }
    }

    info!("Removing \"hello_key\" record from database...");
    let r = runtime
        .block_on(client.remove("hello_key".to_string()))
        .unwrap();
    assert_eq!(r, Some("hello_value".to_string())); // key should exist in db while removing it

    info!("Getting \"hello_key\" to check whether it still exists...");
    let r = runtime
        .block_on(client.get("hello_key".to_string()))
        .unwrap();
    match r {
        Some(_) => info!("Key still exists."),
        None => info!("Key not found anymore"),
    }
    assert_eq!(r, None); // key should not exist in db anymore

    info!("Simple key/value client finished.")
}
