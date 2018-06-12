extern crate ekiden_common;
extern crate ekiden_ethereum;
extern crate ekiden_registry_base;
extern crate ekiden_storage_dummy;

#[macro_use(defer)]
extern crate scopeguard;
extern crate web3;

use std::sync::Arc;

use ekiden_common::bytes::{B256, H160};
use ekiden_common::contract::Contract;
use ekiden_common::entity::Entity;
use ekiden_common::error::Error;
use ekiden_common::futures::{cpupool, future, Future, Stream};
use ekiden_common::ring::signature::Ed25519KeyPair;
use ekiden_common::signature::{InMemorySigner, Signed};
use ekiden_common::testing;
use ekiden_common::untrusted;
use ekiden_ethereum::truffle::{deploy_truffle, mine, start_truffle, DEVELOPMENT_ADDRESS};
use ekiden_ethereum::EthereumContractRegistryBackend;
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
    let address = addresses
        .get("ContractRegistryOasis")
        .expect("could not find contract address");

    // Run a driver to make some background transactions such that things confirm.
    let tx_stream = mine(transport);
    let _handle = executor.spawn(tx_stream.fold(0 as u64, |a, _b| future::ok::<u64, Error>(a)));

    // Generate contract. identity.
    let con_sk =
        Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(&B256::random())).unwrap();

    let mut con = Contract::default();
    con.id = B256::from(con_sk.public_key_bytes());

    // Launch the registry.
    let storage = DummyStorageBackend::new();
    let registry = EthereumContractRegistryBackend::new(
        Arc::new(client),
        Arc::new(Entity {
            id: B256::zero(),
            eth_address: Some(H160::from_slice(DEVELOPMENT_ADDRESS)),
        }),
        H160::from_slice(&address),
        Arc::new(storage),
        &mut executor,
    ).expect("Couldn't initialize registry.");

    let contract_signer = InMemorySigner::new(con_sk);
    let signed_con = Signed::sign(
        &contract_signer,
        &REGISTER_CONTRACT_SIGNATURE_CONTEXT,
        con.clone(),
    );
    let verify_id = con.id.clone();
    let _task = registry
        .register_contract(signed_con)
        .then(move |r| {
            assert!(r.is_ok());
            registry.get_contract(con.id)
        })
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
