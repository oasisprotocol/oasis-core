#[macro_use]
extern crate clap;
extern crate ekiden_client;
extern crate ekiden_runtime;
extern crate grpcio;
extern crate simple_keyvalue_api;
extern crate tokio;

use std::sync::Arc;

use clap::{App, Arg, SubCommand};
use grpcio::EnvBuilder;
use tokio::runtime::Runtime;

use ekiden_client::{create_txn_api_client, Node, TxnClient};
use ekiden_runtime::common::runtime::RuntimeId;
use simple_keyvalue_api::{with_api, KeyValue};

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
        };
        eprintln!(
            "Storing \"{}\" as key and \"{}\" as value to database...",
            kv.key, kv.value,
        );
        rt.block_on(kv_client.insert(kv)).unwrap();
    } else if let Some(matches) = matches.subcommand_matches("get") {
        let key = String::from(matches.value_of("KEY").unwrap());
        eprintln!("Getting value for key \"{}\"...", key);
        println!("{}", rt.block_on(kv_client.get(key)).unwrap().unwrap());
    }

    eprintln!("Simple key/value operation client finished.");
}
