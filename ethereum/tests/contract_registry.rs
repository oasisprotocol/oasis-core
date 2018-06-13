extern crate ekiden_beacon_base;
extern crate ekiden_common;
extern crate ekiden_ethereum;
extern crate ekiden_registry_base;
extern crate ekiden_storage_dummy;

#[macro_use(defer)]
extern crate scopeguard;
extern crate web3;

use std::sync::Arc;
use std::{thread, time};

use ekiden_beacon_base::backend::RandomBeacon;
use ekiden_common::bytes::{B256, H160};
use ekiden_common::contract::Contract;
use ekiden_common::entity::Entity;
use ekiden_common::error::Error;
use ekiden_common::futures::{cpupool, future, stream, Future, Stream};
use ekiden_common::ring::signature::Ed25519KeyPair;
use ekiden_common::signature::{InMemorySigner, Signed};
use ekiden_common::testing;
use ekiden_common::untrusted;
use ekiden_ethereum::truffle::{deploy_truffle, mine, start_truffle, DEVELOPMENT_ADDRESS};
use ekiden_ethereum::{EthereumContractRegistryBackend, EthereumMockTime, EthereumRandomBeacon};
use ekiden_registry_base::contract_backend::{ContractRegistryBackend,
                                             REGISTER_CONTRACT_SIGNATURE_CONTEXT};
use ekiden_storage_dummy::DummyStorageBackend;
use web3::api::Web3;
use web3::transports::WebSocket;

#[test]
fn test_contract_registry_ethereum_roundtrip() {
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
    let addresses = deploy_truffle(env!("CARGO_MANIFEST_DIR"));
    let time_address = addresses
        .get("MockEpoch")
        .expect("could not find contract address");
    let beacon_address = addresses
        .get("RandomBeaconMock")
        .expect("could not find contract address");
    let contract_address = addresses
        .get("ContractRegistryMock")
        .expect("could not find contract address");

    // Run a driver to make some background transactions such that things confirm.
    let tx_stream = mine(transport);
    let _handle = executor.spawn(tx_stream.fold(0 as u64, |a, _b| future::ok::<u64, Error>(a)));

    // Generate contract. identity.
    let con_sk =
        Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(&B256::random())).unwrap();

    let mut con = Contract::default();
    con.id = B256::from(con_sk.public_key_bytes());

    let client = Arc::new(client);
    let entity = Arc::new(Entity {
        id: B256::zero(),
        eth_address: Some(H160::from_slice(DEVELOPMENT_ADDRESS)),
    });

    // Run a driver to advance time so that things confirm.
    let time_source = Arc::new(
        EthereumMockTime::new(
            client.clone(),
            entity.clone(),
            H160::from_slice(&time_address),
            &mut executor,
        ).unwrap(),
    );

    // Run a driver to make some background transactions such that things confirm.
    let local_source = time_source.clone();
    let time_stream = Box::new(stream::unfold(0, move |state| {
        thread::sleep(time::Duration::from_millis(500));
        Some(
            local_source
                .set_mock_time(state, 10)
                .then(move |_r| future::ok::<(u64, u64), Error>((0, state + 1))),
        )
    }));
    let _time_handle =
        executor.spawn(time_stream.fold(0 as u64, |a, _b| future::ok::<u64, Error>(a)));

    // Make a beacon.
    let beacon = EthereumRandomBeacon::new(
        client.clone(),
        entity.clone(),
        H160::from_slice(&beacon_address),
        time_source.clone(),
    ).unwrap();
    beacon.start(&mut executor);

    // Launch the registry.
    let storage = DummyStorageBackend::new();
    let registry = EthereumContractRegistryBackend::new(
        client.clone(),
        entity.clone(),
        H160::from_slice(&contract_address),
        Arc::new(storage),
        Arc::new(beacon),
        &mut executor,
    ).expect("Couldn't initialize registry.");

    let contract_signer = InMemorySigner::new(con_sk);
    let signed_con = Signed::sign(
        &contract_signer,
        &REGISTER_CONTRACT_SIGNATURE_CONTEXT,
        con.clone(),
    );
    let verify_id = con.id.clone();
    let time_advance = time_source.clone();
    let _task = registry
        .register_contract(signed_con)
        .then(move |r| {
            assert!(r.is_ok());
            time_advance.set_mock_time(100, 0)
        })
        .then(move |_r| registry.get_contract(con.id))
        .then(move |contract| {
            println!("{:?}", contract);
            assert!(contract.is_ok());

            let contract = contract.unwrap();
            assert!(contract.id == verify_id);

            drop(handle);
            future::ok::<(), ()>(())
        })
        .wait();
}
