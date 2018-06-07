use std::sync::Arc;

extern crate ekiden_beacon_base;
extern crate ekiden_common;
extern crate ekiden_ethereum;
#[macro_use(defer)]
extern crate scopeguard;
extern crate web3;

use ekiden_beacon_base::RandomBeacon;
use ekiden_common::bytes::{B256, H160};
use ekiden_common::entity::Entity;
use ekiden_common::epochtime::local::{LocalTimeSourceNotifier, SystemTimeSource};
use ekiden_common::error::Error;
use ekiden_common::futures::{cpupool, future, Future, Stream};
use ekiden_common::testing;
use ekiden_ethereum::truffle::{deploy_truffle, mine, start_truffle, DEVELOPMENT_ADDRESS};
use ekiden_ethereum::EthereumRandomBeacon;
use web3::api::Web3;
use web3::transports::WebSocket;

#[test]
fn beacon_integration() {
    testing::try_init_logging();

    let mut executor = cpupool::CpuPool::new(4);

    // Spin up truffle.
    let mut truffle = start_truffle(env!("CARGO_MANIFEST_DIR"));
    defer! {{
        let _ = truffle.kill();
    }};

    // Connect to truffle.
    let (handle, transport) = WebSocket::new("ws://localhost:9545").unwrap();
    let client = Web3::new(transport.clone());

    // Make sure our contracts are deployed.
    let address = deploy_truffle("RandomBeacon", env!("CARGO_MANIFEST_DIR"));

    // Run a driver to make some background transactions such that things confirm.
    let tx_stream = mine(transport);
    let _handle = executor.spawn(tx_stream.fold(0 as u64, |a, _b| future::ok::<u64, Error>(a)));

    // Initialize the beacon.
    let time_source = Arc::new(SystemTimeSource {});
    let time_notifier = Arc::new(LocalTimeSourceNotifier::new(time_source.clone()));
    let beacon = EthereumRandomBeacon::new(
        Arc::new(client),
        Arc::new(Entity {
            id: B256::zero(),
            eth_address: Some(H160::from_slice(DEVELOPMENT_ADDRESS)),
        }),
        H160::from_slice(&address),
        time_notifier.clone(),
    ).unwrap();
    beacon.start(&mut executor);

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

    drop(handle);
}
