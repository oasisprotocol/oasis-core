#[macro_use]
extern crate clap;
extern crate ekiden_client;
extern crate ekiden_runtime;
extern crate grpcio;
extern crate io_context;
extern crate simple_keyvalue_api;
extern crate tokio;

use std::sync::Arc;

use clap::{App, Arg};
use grpcio::EnvBuilder;
use io_context::Context;
use tokio::runtime::Runtime;

use ekiden_client::{
    create_txn_api_client,
    transaction::{Query, QueryCondition, TAG_BLOCK_HASH},
    Node, TxnClient,
};
use ekiden_runtime::{common::runtime::RuntimeId, storage::MKVS};
use simple_keyvalue_api::{with_api, KeyValue};

with_api! {
    create_txn_api_client!(SimpleKeyValueClient, api);
}

fn main() {
    let matches = App::new("Simple key/value runtime test client")
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
    let r: Option<String> = rt.block_on(kv_client.insert(kv)).unwrap();
    assert_eq!(r, None); // key should not exist in db before

    println!("Getting \"hello_key\"...");
    let r = rt.block_on(kv_client.get("hello_key".to_string())).unwrap();
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

    // Test get_latest_block call.
    println!("Getting latest block...");
    let snapshot = rt
        .block_on(kv_client.txn_client().get_latest_block())
        .expect("get latest block snapshot");
    println!("Retrieved block: {:?}", snapshot.block);
    println!("Accessing read-only state snapshot...");
    let r = snapshot
        .get(Context::background(), "hello_key".as_bytes())
        .expect("read-only state get");
    println!(
        "Got \"{}\" ({:?})",
        String::from_utf8(r.clone()).unwrap(),
        r
    );
    assert_eq!(&r[..], "hello_value".as_bytes());

    // Test get_block call.
    for round in 0..=snapshot.block.header.round {
        println!("Getting indexed block {}...", round);
        let snapshot = rt
            .block_on(kv_client.txn_client().get_block(round))
            .expect("get block snapshot")
            .expect("block must exist");

        println!("Retrieved block: {:?}", snapshot.block);
        assert_eq!(snapshot.block.header.round, round);
    }

    let snapshot = rt
        .block_on(kv_client.txn_client().get_block(100000))
        .expect("non-existent block must return None");
    assert!(snapshot.is_none(), "non-existent block must return None");

    println!("Removing \"hello_key\" record from database...");
    let r = rt
        .block_on(kv_client.remove("hello_key".to_string()))
        .unwrap();
    assert_eq!(r, Some("hello_value".to_string())); // key should exist in db while removing it

    println!("Getting \"hello_key\" to check whether it still exists...");
    let r = rt.block_on(kv_client.get("hello_key".to_string())).unwrap();
    match r {
        Some(_) => println!("Key still exists."),
        None => println!("Key not found anymore"),
    }
    assert_eq!(r, None, "key should not exist anymore");

    // Test wait_block_indexed call.
    println!("Waiting for block to be indexed...");
    rt.block_on(kv_client.txn_client().wait_block_indexed(2))
        .expect("wait block indexed");

    // Test query_block call.
    println!("Querying block tags (kv_hello=insert)...");
    let snapshot = rt
        .block_on(kv_client.txn_client().query_block(b"kv_hello", b"insert"))
        .expect("query block snapshot")
        .expect("block must exist");
    println!("Found block: {:?}", snapshot.block);

    println!("Querying block tags (kv_hello=get)...");
    let snapshot = rt
        .block_on(kv_client.txn_client().query_block(b"kv_hello", b"get"))
        .expect("query block snapshot")
        .expect("block must exist");
    println!("Found block: {:?}", snapshot.block);

    // Test query_block call by block hash.
    println!("Querying block by hash ({:?})...", snapshot.block_hash);
    let snapshot = rt
        .block_on(
            kv_client
                .txn_client()
                .query_block(TAG_BLOCK_HASH, snapshot.block_hash),
        )
        .expect("query block snapshot")
        .expect("block must exist");
    println!("Found block: {:?}", snapshot.block);

    // Test get_transactions call.
    println!("Fetching transaction inputs...");
    let txns = rt
        .block_on(
            kv_client
                .txn_client()
                .get_transactions(snapshot.block.header.input_hash),
        )
        .expect("get transactions");
    println!("Found transactions: {:?}", txns);
    assert_eq!(txns.len(), 1);

    // Test query_txn call.
    println!("Querying transaction tags (kv_op=insert)...");
    let snapshot = rt
        .block_on(kv_client.txn_client().query_txn(b"kv_op", b"insert"))
        .expect("query transaction snapshot")
        .expect("transaction must exist");
    println!(
        "Found transaction: index={} input={:?} output={:?}",
        snapshot.index, snapshot.input, snapshot.output
    );

    // Test query_txns call.
    println!("Querying transaction tags (kv_op=insert)...");
    let query = Query {
        round_min: 0,
        round_max: 3,
        conditions: vec![QueryCondition {
            key: b"kv_op".to_vec(),
            values: vec![b"insert".to_vec().into()],
        }],
        limit: 0,
    };
    let txns = rt
        .block_on(kv_client.txn_client().query_txns(query))
        .expect("query transactions");
    println!("Found transactions:");
    for txn in txns {
        println!(
            "round={} index={} input={:?} output={:?}",
            txn.block_snapshot.block.header.round, txn.index, txn.input, txn.output
        );
    }

    println!("Simple key/value client finished.");
}
