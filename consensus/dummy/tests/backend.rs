extern crate ekiden_common;
extern crate ekiden_consensus_base;
extern crate ekiden_consensus_dummy;

use std::sync::Arc;

use ekiden_common::futures::{cpupool, future, Future, Stream};
use ekiden_consensus_base::ConsensusBackend;
use ekiden_consensus_base::test::create_computation_group;
use ekiden_consensus_dummy::DummyConsensusBackend;

#[test]
fn test_dummy_backend_two_rounds() {
    // Create backend with 3 nodes in the computation group.
    let computation_group = Arc::new(create_computation_group(3));
    let backend = Arc::new(DummyConsensusBackend::new(
        // Backend only needs the public part.
        computation_group.iter().map(|n| n.get_public()).collect(),
    ));

    let mut pool = cpupool::CpuPool::new(4);

    // Start backend.
    backend.start(&mut pool);

    // Start all nodes.
    let mut tasks = vec![];
    tasks.append(&mut computation_group
        .iter()
        .map(|n| n.start(backend.clone()))
        .collect());

    // Send compute requests to all nodes.
    for ref node in computation_group.iter() {
        node.compute();
    }

    // Stop when a new block is seen on the chain.
    let wait_rounds = backend.get_blocks().take(3).for_each(move |block| {
        assert!(block.is_internally_consistent());

        match block.header.round.as_u32() {
            0 => {}
            1 => {
                // First round has completed, dispatch a new round of work.
                for ref node in computation_group.iter() {
                    node.compute();
                }
            }
            2 => {
                // Second round has completed, request all nodes to shutdown.
                for ref node in computation_group.iter() {
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
