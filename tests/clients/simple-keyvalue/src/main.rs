#[macro_use]
extern crate clap;
extern crate grpcio;
extern crate io_context;
extern crate oasis_core_client;
extern crate oasis_core_runtime;
extern crate simple_keyvalue_api;
extern crate tokio;

use std::sync::Arc;

use clap::{App, Arg};
use grpcio::EnvBuilder;
use io_context::Context;
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde_bytes::ByteBuf;
use tokio::runtime::Runtime;

use oasis_core_client::{
    create_txn_api_client,
    transaction::{Query, QueryCondition},
    Node, TxnClient,
};
use oasis_core_runtime::{
    common::{crypto::hash::Hash, runtime::RuntimeId},
    storage::MKVS,
};
use simple_keyvalue_api::{with_api, Key, KeyValue};

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
        .arg(Arg::with_name("seed").long("seed").takes_value(true))
        .get_matches();

    let node_address = matches.value_of("node-address").unwrap();
    let runtime_id = value_t_or_exit!(matches, "runtime-id", RuntimeId);
    let nonce_seed = matches
        .value_of("seed")
        .unwrap_or("seeeeeeeeeeeeeeeeeeeeeeeeeeeeeed")
        .as_bytes();

    let h = Hash::digest_bytes(&nonce_seed);
    let mut rng: StdRng = SeedableRng::from_seed(h.into());

    println!("Initializing simple key/value runtime client!");
    let mut rt = Runtime::new().unwrap();
    let env = Arc::new(EnvBuilder::new().build());
    let node = Node::new(env, node_address);
    let txn_client = TxnClient::new(node.channel(), runtime_id, None);
    let kv_client = SimpleKeyValueClient::new(txn_client);

    // Check whether Runtime ID is also set remotely.
    let r: Option<String> = rt.block_on(kv_client.get_runtime_id(())).unwrap();
    assert_eq!(runtime_id.to_string(), r.expect("runtime_id"));

    // Test simple [set,get] key calls
    let mut kv = KeyValue {
        key: String::from("hello_key"),
        value: String::from("hello_value_from_") + &runtime_id.to_string(),
        nonce: Some(rng.gen()),
    };
    let mut k = Key {
        key: kv.key.clone(),
        nonce: Some(rng.gen()),
    };
    println!(
        "Storing \"{}\" as key and \"{}\" as value to database...",
        kv.key, kv.value
    );
    let r: Option<String> = rt.block_on(kv_client.insert(kv.clone())).unwrap();
    assert_eq!(r, None); // key should not exist in db before
    kv.nonce = Some(rng.gen());

    println!("Getting \"{}\"...", k.key);
    let r = rt.block_on(kv_client.get(k.clone())).unwrap();
    match r {
        Some(val) => {
            println!("Got \"{}\"", val);
            assert_eq!(val, kv.value)
        } // key should exist in db
        None => {
            println!("Key not found");
            panic!("Key \"{}\" not found, but it should be.", kv.value)
        }
    }
    k.nonce = Some(rng.gen());

    // Test [set, get] long key calls
    let mut long_kv = KeyValue {
        key: String::from("Unlock the potential of your data without compromising security or privacy"),
        value: String::from("The platform that puts data privacy first. From sharing medical records, to analyzing personal financial information etc."),
        nonce: Some(rng.gen()),
    };
    let mut long_k = Key {
        key: long_kv.key.clone(),
        nonce: Some(rng.gen()),
    };
    println!("Storing long key and value to database...");
    let r: Option<String> = rt.block_on(kv_client.insert(long_kv.clone())).unwrap();
    assert_eq!(r, None); // key should not exist in db before
    long_kv.nonce = Some(rng.gen());

    println!("Testing runtime message emission...");
    rt.block_on(kv_client.message(rng.gen())).unwrap();

    println!("Getting long key...");
    let r = rt.block_on(kv_client.get(long_k.clone())).unwrap();
    match r {
        Some(val) => {
            println!("Got correct long value");
            assert_eq!(val, long_kv.value)
        } // key should exist in db
        None => {
            println!("Key not found");
            panic!("Long key not found, but it should be.")
        }
    }
    long_k.nonce = Some(rng.gen());

    // Test get_latest_block call.
    println!("Getting latest block...");
    let snapshot = rt
        .block_on(kv_client.txn_client().get_latest_block())
        .expect("get latest block snapshot");
    println!("Retrieved block: {:?}", snapshot.block);
    println!("Accessing read-only state snapshot...");
    let r = snapshot
        .get(Context::background(), kv.key.as_bytes())
        .expect("read-only state get");
    println!(
        "Got \"{}\" ({:?})",
        String::from_utf8(r.clone()).unwrap(),
        r
    );
    assert_eq!(&r[..], kv.value.as_bytes());

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

    let latest_snapshot = snapshot;
    let snapshot = rt
        .block_on(kv_client.txn_client().get_block(100000))
        .expect("non-existent block must return None");
    assert!(snapshot.is_none(), "non-existent block must return None");

    println!("Removing \"{}\" record from database...", k.key);
    let r = rt.block_on(kv_client.remove(k.clone())).unwrap();
    assert_eq!(r, Some(kv.value)); // key should exist in db while removing it
    k.nonce = Some(rng.gen());

    println!("Getting \"{}\" to check whether it still exists...", kv.key);
    let r = rt.block_on(kv_client.get(k.clone())).unwrap();
    match r {
        Some(_) => println!("Key still exists."),
        None => println!("Key not found anymore"),
    }
    assert_eq!(r, None, "key should not exist anymore");
    k.nonce = Some(rng.gen());

    // Test wait_block_indexed call.
    println!("Waiting for block to be indexed...");
    let latest_round = latest_snapshot.block.header.round;
    rt.block_on(kv_client.txn_client().wait_block_indexed(latest_round))
        .expect("wait block indexed");

    // Test get_block_by_hash call.
    println!(
        "Querying block by hash ({:?})...",
        latest_snapshot.block_hash
    );
    let snapshot = rt
        .block_on(
            kv_client
                .txn_client()
                .get_block_by_hash(latest_snapshot.block_hash),
        )
        .expect("query block snapshot")
        .expect("block must exist");
    println!("Found block: {:?}", snapshot.block);

    // Test get_txs call.
    println!("Fetching transaction inputs...");
    let txns = rt
        .block_on(
            kv_client
                .txn_client()
                .get_txs(snapshot.block.header.round, snapshot.block.header.io_root),
        )
        .expect("get transactions");
    println!("Found transactions: {:?}", txns);
    assert_eq!(txns.len(), 1);

    // Test query_tx call.
    println!("Querying transaction tags (kv_op=insert)...");
    let snapshot = rt
        .block_on(kv_client.txn_client().query_tx(b"kv_op", b"insert"))
        .expect("query transaction snapshot")
        .expect("transaction must exist");
    println!(
        "Found transaction: index={} input={:?} output={:?}",
        snapshot.index, snapshot.input, snapshot.output
    );

    // Test query_txs call.
    println!("Querying transaction tags (kv_op=insert)...");
    let query = Query {
        round_min: 0,
        round_max: latest_round,
        conditions: vec![QueryCondition {
            key: b"kv_op".to_vec(),
            values: vec![ByteBuf::from(b"insert".to_vec())],
        }],
        limit: 0,
    };
    let txns = rt
        .block_on(kv_client.txn_client().query_txs(query))
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
