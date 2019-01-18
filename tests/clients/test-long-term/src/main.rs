#[macro_use]
extern crate clap;
extern crate rand;

#[macro_use]
extern crate client_utils;
extern crate ekiden_core;
extern crate ekiden_rpc_client;
extern crate ekiden_runtime_client;

extern crate simple_keyvalue_api;

use std::{thread, time};

use clap::{App, Arg};

use ekiden_core::tokio;
use ekiden_runtime_client::create_runtime_client;
use simple_keyvalue_api::{with_api, KeyValue};

with_api! {
    create_runtime_client!(simple_keyvalue, simple_keyvalue_api, api);
}

fn main() {
    let client = runtime_client!(simple_keyvalue);
    let mut runtime = tokio::runtime::Runtime::new().unwrap();

    let kv = KeyValue {
        key: String::from("my_key"),
        value: String::from("my_value"),
    };
    let r = runtime.block_on(client.insert(kv)).unwrap();
    assert_eq!(r, None); // key should not exist in db before

    // Check value.
    let r = runtime.block_on(client.get("my_key".to_string())).unwrap();
    assert_eq!(r.unwrap(), "my_value".to_string()); // key should exist in db

    // Sleep for 10 seconds to allow for epoch to advance.
    thread::sleep(time::Duration::from_secs(10));

    // Check value again.
    let r = runtime.block_on(client.get("my_key".to_string())).unwrap();
    assert_eq!(r.unwrap(), "my_value".to_string()); // key should still exist in db
}
