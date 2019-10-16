extern crate clap;
extern crate grpcio;
extern crate oasis_core_client;
extern crate oasis_core_runtime;
extern crate staking_arbitrary_api;

use std::sync::Arc;

use clap::{value_t_or_exit, App, Arg};
use grpcio::EnvBuilder;
use tokio::runtime::Runtime;

use oasis_core_client::{create_txn_api_client, Node, TxnClient};
use oasis_core_runtime::common::{crypto::signature::PublicKey, runtime::RuntimeId};
use staking_arbitrary_api::{with_api, AccountAmount};

with_api! {
    create_txn_api_client!(StakingArbitraryClient, api);
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

    let env = Arc::new(EnvBuilder::new().build());
    let node = Node::new(env, node_address);
    let txn_client = TxnClient::new(node.channel(), runtime_id, None);
    let sa_client = StakingArbitraryClient::new(txn_client);

    let mut rt = Runtime::new().unwrap();
    let account = PublicKey(*b"UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU");

    println!("Increasing.");
    rt.block_on(sa_client.increase(AccountAmount {
        account,
        amount: vec![0x01, 0x0f, 0x00],
    }))
    .unwrap();

    println!("Decreasing.");
    rt.block_on(sa_client.decrease(AccountAmount {
        account,
        amount: vec![0x01, 0x0f, 0x00],
    }))
    .unwrap();

    println!("Done.");
}
