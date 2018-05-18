extern crate ekiden_beacon_dummy;
extern crate ekiden_common;
extern crate ekiden_consensus_base;
extern crate ekiden_consensus_dummy;
extern crate ekiden_registry_base;
extern crate ekiden_registry_dummy;
extern crate ekiden_scheduler_dummy;
extern crate ekiden_storage_dummy;

use std::sync::Arc;

use ekiden_beacon_dummy::InsecureDummyRandomBeacon;
use ekiden_common::bytes::B256;
use ekiden_common::contract::Contract;
use ekiden_common::epochtime::{SystemTimeSource, TimeSourceNotifier};
use ekiden_common::futures::{cpupool, future, Future, Stream};
use ekiden_common::ring::signature::Ed25519KeyPair;
use ekiden_common::signature::{InMemorySigner, Signed};
use ekiden_common::untrusted;
use ekiden_consensus_base::ConsensusBackend;
use ekiden_consensus_base::test::generate_simulated_nodes;
use ekiden_consensus_dummy::DummyConsensusBackend;
use ekiden_registry_base::{ContractRegistryBackend, REGISTER_CONTRACT_SIGNATURE_CONTEXT};
use ekiden_registry_base::test::populate_entity_registry;
use ekiden_registry_dummy::{DummyContractRegistryBackend, DummyEntityRegistryBackend};
use ekiden_scheduler_dummy::DummySchedulerBackend;
use ekiden_storage_dummy::DummyStorageBackend;

#[test]
fn test_dummy_backend_two_rounds() {
    // Number of simulated nodes to create.
    const NODE_COUNT: usize = 3;

    let time_source = Arc::new(SystemTimeSource {});
    let time_notifier = Arc::new(TimeSourceNotifier::new(time_source.clone()));

    let beacon = Arc::new(InsecureDummyRandomBeacon::new(time_notifier.clone()));
    let entity_registry = Arc::new(DummyEntityRegistryBackend::new());
    let contract_registry = Arc::new(DummyContractRegistryBackend::new());
    let contract_sk =
        Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(&B256::random())).unwrap();
    let contract = Contract {
        id: B256::from(contract_sk.public_key_bytes()),
        store_id: B256::random(),
        code: vec![],
        minimum_bond: 0,
        mode_nondeterministic: false,
        features_sgx: false,
        advertisement_rate: 0,
        replica_group_size: NODE_COUNT as u64,
        storage_group_size: NODE_COUNT as u64,
    };
    let contract_signer = InMemorySigner::new(contract_sk);
    let signed_contract = Signed::sign(
        &contract_signer,
        &REGISTER_CONTRACT_SIGNATURE_CONTEXT,
        contract.clone(),
    );

    contract_registry
        .register_contract(signed_contract)
        .wait()
        .unwrap();
    let contract = Arc::new(contract);

    let scheduler = Arc::new(DummySchedulerBackend::new(
        beacon.clone(),
        contract_registry.clone(),
        entity_registry.clone(),
        time_notifier.clone(),
    ));
    let storage = Arc::new(DummyStorageBackend::new());

    // Generate simulated nodes and populate registry with them.
    let nodes = Arc::new(generate_simulated_nodes(NODE_COUNT, storage.clone()));
    populate_entity_registry(
        entity_registry.clone(),
        nodes.iter().map(|node| node.get_public_key()).collect(),
    );

    let nodes = Arc::new(nodes);

    // Create dummy consensus backend.
    let backend = Arc::new(DummyConsensusBackend::new(contract, scheduler, storage));

    let mut pool = cpupool::CpuPool::new(4);

    // Start backend.
    backend.start(&mut pool);

    // Start all nodes.
    let mut tasks = vec![];
    tasks.append(&mut nodes.iter().map(|n| n.start(backend.clone())).collect());

    // Send compute requests to all nodes.
    for ref node in nodes.iter() {
        node.compute();
    }

    // Stop when a new block is seen on the chain.
    let wait_rounds = backend.get_blocks().take(3).for_each(move |block| {
        assert!(block.is_internally_consistent());

        match block.header.round.as_u32() {
            0 => {}
            1 => {
                // First round has completed, dispatch a new round of work.
                for ref node in nodes.iter() {
                    node.compute();
                }
            }
            2 => {
                // Second round has completed, request all nodes to shutdown.
                for ref node in nodes.iter() {
                    node.shutdown();
                }

                let backend = backend.clone();
                backend.shutdown();
            }
            round => panic!("incorrect round number: {}", round),
        }

        Ok(())
    });

    tasks.push(Box::new(wait_rounds));

    // Wait for all tasks to finish.
    pool.spawn(future::join_all(tasks)).wait().unwrap();
}
