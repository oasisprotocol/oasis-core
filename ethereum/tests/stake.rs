use std::sync::Arc;

extern crate ekiden_stake_base;
extern crate ekiden_common;
extern crate ekiden_epochtime;
extern crate ekiden_ethereum;
#[macro_use(defer)]
extern crate scopeguard;
extern crate grpcio;
extern crate web3;
#[macro_use]
extern crate log;

use ekiden_stake_base::StakeEscrowBackend;
use ekiden_common::bytes::{B256, H160};
use ekiden_common::entity::Entity;
use ekiden_common::futures::prelude::*;
use ekiden_common::testing;
use ekiden_ethereum::truffle::{deploy_truffle, start_truffle, DEVELOPMENT_ADDRESS};
use ekiden_ethereum::EthereumStake;
use web3::api::Web3;
use web3::transports::WebSocket;

#[test]
fn stake_integration() {
    testing::try_init_logging();

    // Spin up truffle.
    let mut truffle = start_truffle(env!("CARGO_MANIFEST_DIR"));
    defer! {{
        drop(truffle.kill());
    }};

    // Connect to truffle.
    let (handle, transport) = WebSocket::new("ws://localhost:9545").unwrap();
    let client = Web3::new(transport.clone());

    // Make sure our contracts are deployed.
    let addresses = deploy_truffle(env!("CARGO_MANIFEST_DIR"));
    let address = addresses
        .get("Stake")
        .expect("could not find contract address");

    let stake = EthereumStake::new(
        Arc::new(client),
        Arc::new(Entity {
            id: B256::zero(),
            eth_address: Some(H160::from_slice(DEVELOPMENT_ADDRESS)),
        }),
        H160::from_slice(&address),
    ).unwrap();

    let name = stake.get_name().wait().unwrap();
    debug!("name = {}", name);

    drop(handle);
}
