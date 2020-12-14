use std::sync::Arc;

use clap::{value_t_or_exit, App, Arg};
use grpcio::EnvBuilder;
use io_context::Context;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::runtime::Runtime;

use oasis_core_client::{create_txn_api_client, Node, TxnClient};
use oasis_core_keymanager_client::{self, KeyManagerClient, KeyPairId};
use oasis_core_runtime::common::{crypto::hash::Hash, runtime::RuntimeId};
use simple_keyvalue_api::{with_api, Key, KeyValue, Transfer, Withdraw};

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
        .arg(
            Arg::with_name("key")
                .long("key")
                .takes_value(true)
                .default_value("hello_key")
                .required(true),
        )
        .arg(Arg::with_name("seed").long("seed").takes_value(true))
        .get_matches();

    let node_address = matches.value_of("node-address").unwrap();
    let runtime_id = value_t_or_exit!(matches, "runtime-id", RuntimeId);
    let k = matches.value_of("key").unwrap();
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

    let kv = KeyValue {
        key: k.to_owned(),
        value: String::from("hello_value"),
        nonce: rng.gen(),
    };
    let mut key = Key {
        key: k.to_owned(),
        nonce: rng.gen(),
    };
    println!(
        "Storing \"{}\" as key and \"{}\" as value to database...",
        kv.key, kv.value
    );
    let r: Option<String> = rt.block_on(kv_client.enc_insert(kv)).unwrap();
    assert_eq!(r, None); // key should not exist in db before

    println!("Getting \"{}\"...", key.key);
    let r = rt.block_on(kv_client.enc_get(key.clone())).unwrap();
    match r {
        Some(val) => {
            println!("Got \"{}\"", val);
            assert_eq!(val, "hello_value")
        } // key should exist in db
        None => {
            println!("Key not found");
            panic!("Key \"{}\" not found, but it should be.", key.key)
        }
    }
    key.nonce = rng.gen();

    println!("Removing \"{}\" record from database...", key.key);
    let r = rt.block_on(kv_client.enc_remove(key.clone())).unwrap();
    assert_eq!(r, Some("hello_value".to_string())); // key should exist in db while removing it
    key.nonce = rng.gen();

    println!(
        "Getting \"{}\" to check whether it still exists...",
        key.key
    );
    let r = rt.block_on(kv_client.enc_get(key.clone())).unwrap();
    match r {
        Some(_) => println!("Key still exists."),
        None => println!("Key not found anymore"),
    }
    assert_eq!(r, None, "key should not exist anymore");
    key.nonce = rng.gen();

    // Test that key manager connection via EnclaveRPC works.
    println!("Testing key manager connection via gRPC transport...");
    // TODO: Key manager MRENCLAVE.
    let km_client = Arc::new(oasis_core_keymanager_client::RemoteClient::new_grpc(
        runtime_id,
        None,
        node.channel(),
        1024,
    ));

    // Request public key for some "key pair id".
    let key_pair_id = KeyPairId::from(Hash::empty_hash().as_ref());
    let r = rt
        .block_on(km_client.get_public_key(Context::background(), key_pair_id))
        .unwrap();
    assert!(r.is_some(), "get_public_key should return a public key");
    let pkey = r;

    let r = rt
        .block_on(km_client.get_public_key(Context::background(), key_pair_id))
        .unwrap();
    assert_eq!(r, pkey, "get_public_key should return the same public key");

    println!("Simple key/value client finished.");
}
