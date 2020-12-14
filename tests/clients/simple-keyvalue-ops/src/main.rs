use std::sync::Arc;

use clap::{value_t_or_exit, App, Arg, SubCommand};
use grpcio::EnvBuilder;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::runtime::Runtime;

use oasis_core_client::{create_txn_api_client, Node, TxnClient};
use oasis_core_runtime::common::{crypto::hash::Hash, runtime::RuntimeId};
use simple_keyvalue_api::{with_api, Key, KeyValue, Transfer, Withdraw};

with_api! {
    create_txn_api_client!(KeyValueOpsClient, api);
}

fn main() {
    let matches = App::new("Simple key/value operation client")
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
        .subcommand(
            SubCommand::with_name("set")
                .about("Store a key/value pair")
                .arg(Arg::with_name("KEY").required(true).index(1))
                .arg(Arg::with_name("VALUE").required(true).index(2)),
        )
        .subcommand(
            SubCommand::with_name("get")
                .about("Get a value")
                .arg(Arg::with_name("KEY").required(true).index(1)),
        )
        .get_matches();

    let node_address = matches.value_of("node-address").unwrap();
    let runtime_id = value_t_or_exit!(matches, "runtime-id", RuntimeId);
    let nonce_seed = matches
        .value_of("seed")
        .unwrap_or("seeeeeeeeeeeeeeeeeeeeeeeeeeeeeed")
        .as_bytes();

    let h = Hash::digest_bytes(&nonce_seed);
    let mut rng: StdRng = SeedableRng::from_seed(h.into());

    eprintln!("Initializing simple key/value operation client!");
    let mut rt = Runtime::new().unwrap();
    let env = Arc::new(EnvBuilder::new().build());
    let node = Node::new(env, node_address);
    let txn_client = TxnClient::new(node.channel(), runtime_id, None);
    let kv_client = KeyValueOpsClient::new(txn_client);

    if let Some(matches) = matches.subcommand_matches("set") {
        let kv = KeyValue {
            key: matches.value_of("KEY").unwrap().into(),
            value: matches.value_of("VALUE").unwrap().into(),
            nonce: Some(rng.gen()),
        };
        eprintln!(
            "Storing \"{}\" as key and \"{}\" as value to database...",
            kv.key, kv.value,
        );
        rt.block_on(kv_client.insert(kv)).unwrap();
    } else if let Some(matches) = matches.subcommand_matches("get") {
        let key = Key {
            key: matches.value_of("KEY").unwrap().into(),
            nonce: Some(rng.gen()),
        };
        eprintln!("Getting value for key \"{}\"...", key.key);
        println!("{}", rt.block_on(kv_client.get(key)).unwrap().unwrap());
    }

    eprintln!("Simple key/value operation client finished.");
}
