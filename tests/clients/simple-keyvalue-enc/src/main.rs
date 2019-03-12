#[macro_use]
extern crate clap;
extern crate ekiden_client;
extern crate ekiden_runtime;
extern crate grpcio;
extern crate simple_keyvalue_api;
extern crate tokio;

use std::sync::Arc;

use clap::{App, Arg};
use grpcio::EnvBuilder;
use tokio::runtime::Runtime;

use ekiden_client::{create_txn_api_client, Node, TxnClient};
use ekiden_runtime::common::runtime::RuntimeId;
use simple_keyvalue_api::{with_api, KeyValue};

with_api! {
    create_txn_api_client!(SimpleKeyValueClient, api);
}

fn main() {
    let matches = App::new("Simple key/value runtime test client (with encryption)")
        .arg(
            Arg::with_name("runtime-id")
                .long("runtime-id")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("node-address")
                .long("node-address")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    let node_address = matches.value_of("node-address").unwrap();
    let runtime_id = value_t_or_exit!(matches, "runtime-id", RuntimeId);

    println!("Initializing simple key/value runtime client!");
    let mut rt = Runtime::new().unwrap();
    let env = Arc::new(EnvBuilder::new().build());
    let node = Node::new(env, node_address);
    let txn_client = TxnClient::new(node.channel(), runtime_id, None);
    let kv_client = SimpleKeyValueClient::new(txn_client);

    let kv = KeyValue {
        key: String::from("hello_key"),
        value: String::from("hello_value"),
    };
    println!(
        "Storing \"{}\" as key and \"{}\" as value to database...",
        kv.key, kv.value
    );
    let r: Option<String> = rt.block_on(kv_client.enc_insert(kv)).unwrap();
    assert_eq!(r, None); // key should not exist in db before

    println!("Getting \"hello_key\"...");
    let r = rt
        .block_on(kv_client.enc_get("hello_key".to_string()))
        .unwrap();
    match r {
        Some(val) => {
            println!("Got \"{}\"", val);
            assert_eq!(val, "hello_value")
        } // key should exist in db
        None => {
            println!("Key not found");
            panic!("Key \"hello_value\" not found, but it should be.")
        }
    }

    println!("Removing \"hello_key\" record from database...");
    let r = rt
        .block_on(kv_client.enc_remove("hello_key".to_string()))
        .unwrap();
    assert_eq!(r, Some("hello_value".to_string())); // key should exist in db while removing it

    println!("Getting \"hello_key\" to check whether it still exists...");
    let r = rt
        .block_on(kv_client.enc_get("hello_key".to_string()))
        .unwrap();
    match r {
        Some(_) => println!("Key still exists."),
        None => println!("Key not found anymore"),
    }
    assert_eq!(r, None, "key should not exist anymore");

    println!("Simple key/value client finished.");
}
