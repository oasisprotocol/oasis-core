use std::sync::Arc;

extern crate ekiden_beacon_base;
extern crate ekiden_common;
extern crate ekiden_epochtime;
extern crate ekiden_ethereum;
#[macro_use(defer)]
extern crate scopeguard;
extern crate grpcio;
extern crate web3;

use ekiden_beacon_base::RandomBeacon;
use ekiden_common::bytes::{B256, H160};
use ekiden_common::entity::Entity;
use ekiden_common::environment::{Environment, GrpcEnvironment};
use ekiden_common::futures::prelude::*;
use ekiden_common::testing;
use ekiden_epochtime::interface::EPOCH_INTERVAL;
use ekiden_epochtime::local::{LocalTimeSourceNotifier, SystemTimeSource};
use ekiden_ethereum::truffle::{deploy_truffle, mine, start_truffle, DEVELOPMENT_ADDRESS};
use ekiden_ethereum::EthereumRandomBeacon;
use web3::api::Web3;
use web3::transports::WebSocket;

#[test]
fn beacon_integration() {
    testing::try_init_logging();

    let grpc_environment = grpcio::EnvBuilder::new().build();
    let environment = Arc::new(GrpcEnvironment::new(grpc_environment));

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
        .get("RandomBeaconOasis")
        .expect("could not find contract address");

    // Run a driver to make some background transactions such that things confirm.
    environment.spawn(mine(transport).discard());

    // Initialize the beacon.
    let time_source = Arc::new(SystemTimeSource {
        interval: EPOCH_INTERVAL,
    });
    let time_notifier = Arc::new(LocalTimeSourceNotifier::new(time_source.clone()));
    let beacon = EthereumRandomBeacon::new(
        environment.clone(),
        Arc::new(client),
        Arc::new(Entity {
            id: B256::zero(),
            eth_address: Some(H160::from_slice(DEVELOPMENT_ADDRESS)),
        }),
        H160::from_slice(&address),
        time_notifier.clone(),
    ).unwrap();

    // Pump the time source.
    time_notifier.notify_subscribers().unwrap();

    // Subscribe to the beacon.
    let get_beacons = beacon.watch_beacons().take(1).collect();
    let beacons = get_beacons.wait().unwrap();

    // Ensure that there is at least one beacon.
    assert!(beacons.len() >= 1);
    let (epoch, entropy) = beacons[0];

    // Poll the beacon and ensure the output matches.
    let polled_entropy = beacon
        .get_beacon(epoch)
        .wait()
        .expect("failed to get beacon");
    assert_eq!(entropy, polled_entropy);

    // Ensure that there is a cached block number for the current epoch.
    let block_number = beacon
        .get_block_for_epoch(epoch)
        .expect("no block for epoch");
    assert!(block_number > 0); // This is usually `7` but that's not guaranteed.

    drop(handle);
}
