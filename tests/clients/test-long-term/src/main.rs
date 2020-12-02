use std::{sync::Arc, thread, time};

use clap::{value_t_or_exit, App, Arg};
use grpcio::EnvBuilder;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::runtime::Runtime;

use oasis_core_client::{create_txn_api_client, Node, TxnClient};
use oasis_core_runtime::common::{crypto::hash::Hash, runtime::RuntimeId};
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
        .arg(
            Arg::with_name("mode")
                .long("mode")
                .help("client operation mode")
                .takes_value(true)
                .possible_values(&["sleep", "part1", "part1-nomsg", "part2"])
                .default_value("sleep"),
        )
        .arg(
            Arg::with_name("sleep-for")
                .long("sleep-for")
                .help("amount of seconds to sleep for in sleep mode")
                .takes_value(true)
                .default_value("60"),
        )
        .arg(Arg::with_name("seed").long("seed").takes_value(true))
        .get_matches();

    let node_address = matches.value_of("node-address").unwrap();
    let runtime_id = value_t_or_exit!(matches, "runtime-id", RuntimeId);
    let mode = matches.value_of("mode").unwrap();
    let nonce_seed = matches
        .value_of("seed")
        .unwrap_or("seeeeeeeeeeeeeeeeeeeeeeeeeeeeeed")
        .as_bytes();

    let h = Hash::digest_bytes(&nonce_seed);
    let mut rng: StdRng = SeedableRng::from_seed(h.into());

    println!("Initializing simple key/value runtime!");
    let mut rt = Runtime::new().unwrap();
    let env = Arc::new(EnvBuilder::new().build());
    let node = Node::new(env, node_address);
    let txn_client = TxnClient::new(node.channel(), runtime_id, None);
    let kv_client = SimpleKeyValueClient::new(txn_client);

    let mut kv = KeyValue {
        key: String::from("my_key"),
        value: String::from("my_value"),
        nonce: rng.gen(),
    };
    let mut key = Key {
        key: kv.key.to_owned(),
        nonce: rng.gen(),
    };

    if mode == "sleep" || mode == "part1" || mode == "part1-nomsg" {
        println!("Inserting key/value pair");
        let r = rt.block_on(kv_client.insert(kv.clone())).unwrap();
        assert_eq!(r, None); // key should not exist in db before
        kv.nonce = rng.gen();

        // Check value.
        println!("Checking if key exists and has the correct value");
        let r = rt.block_on(kv_client.get(key.clone())).unwrap();
        assert_eq!(r.unwrap(), kv.value); // key should exist in db
        key.nonce = rng.gen();

        if mode != "part1-nomsg" {
            // Emit message so emitted messages will be pending before epoch transition.
            println!("Testing runtime message emission...");
            rt.block_on(kv_client.message(rng.gen())).unwrap();
        }
    }

    if mode == "sleep" {
        let sleep_for = value_t_or_exit!(matches, "sleep-for", u64);

        // Sleep to allow for epoch to advance.
        println!("Sleeping for {} seconds", sleep_for);
        thread::sleep(time::Duration::from_secs(sleep_for));
    }

    if mode == "sleep" || mode == "part2" {
        // Check value again.
        println!("Checking (again) if key exists and has the correct value");
        let r = rt.block_on(kv_client.get(key.clone())).unwrap();
        assert_eq!(r.unwrap(), "my_value".to_string()); // key should still exist in db
    }

    println!("All done");
}
