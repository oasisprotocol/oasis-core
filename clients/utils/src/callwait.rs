use std::collections::HashMap;
use std::sync::Arc;

use serde_cbor;

use ekiden_consensus_base::backend::ConsensusBackend;
use ekiden_consensus_base::block::Block;
use ekiden_core;
use ekiden_core::bytes::B256;
use ekiden_core::bytes::H256;
use ekiden_core::contract::batch::CallBatch;
use ekiden_core::contract::batch::OutputBatch;
use ekiden_core::environment::Environment;
use ekiden_core::error::Error;
use ekiden_core::error::Result;
use ekiden_core::futures::BoxFuture;
use ekiden_core::futures::BoxStream;
use ekiden_core::futures::Future;
use ekiden_core::futures::Stream;
use ekiden_core::hash::EncodedHash;
use ekiden_core::subscribers::StreamSubscribers;
use ekiden_di::di::Container;
use ekiden_storage_base::backend::StorageBackend;

type SharedCommitInfo = Arc<HashMap<H256, Vec<u8>>>;

pub struct Wait {
    stockpile: BoxStream<SharedCommitInfo>,
}

impl Wait {
    pub fn wait_for(self, call_id: H256) -> BoxFuture<Vec<u8>> {
        Box::new(
            self.stockpile
                .filter_map(move |sci: SharedCommitInfo| {
                    sci.get(&call_id).map(|output| output.clone())
                })
                .into_future()
                .then(|r| match r {
                    Ok((Some(output), _rest)) => Ok(output),
                    Ok((None, _rest)) => Err(Error::new("Completion subscription ended")),
                    Err((e, _rest)) => Err(e),
                }),
        )
    }
}

pub struct Manager {
    /// We distribute commitment information here.
    commit_sub: Arc<StreamSubscribers<SharedCommitInfo>>,
    /// For killing our consensus follower task.
    blocks_kill_handle: ekiden_core::futures::KillHandle,
}

impl Manager {
    pub fn new(
        env: &Environment,
        contract_id: B256,
        consensus: &ConsensusBackend,
        storage: Arc<StorageBackend>,
    ) -> Self {
        let commit_sub = Arc::new(StreamSubscribers::new());
        let commit_sub_2 = commit_sub.clone();
        let (watch_blocks, blocks_kill_handle) =
            ekiden_core::futures::killable(consensus.get_blocks(contract_id).for_each(
                move |block: Block| {
                    if block.header.input_hash == ekiden_core::hash::empty_hash() {
                        return Ok(());
                    }

                    // Check what transactions are included in the block. To do that we need to
                    // fetch transactions from storage first.
                    // This wastes local work and storage network effort if we aren't waiting for
                    // anything. We might be able to save this if we add functionality to
                    // `StreamSubscriber` to check if there are no subscriptions.
                    let commit_sub_3 = commit_sub.clone();
                    ekiden_core::futures::spawn(
                        storage
                            .get(block.header.input_hash)
                            .join(storage.get(block.header.output_hash))
                            .and_then(move |(inputs, outputs)| {
                                let inputs: CallBatch = serde_cbor::from_slice(&inputs)?;
                                let outputs: OutputBatch = serde_cbor::from_slice(&outputs)?;
                                let mut commit_info = HashMap::with_capacity(inputs.len());

                                for (input, output) in inputs.iter().zip(outputs.0.into_iter()) {
                                    let call_id = input.get_encoded_hash();

                                    commit_info.insert(call_id, output);
                                }
                                commit_sub_3.notify(&Arc::new(commit_info));

                                Ok(())
                            })
                            .or_else(|error| {
                                error!(
                                    "Failed to fetch transactions from storage: {}",
                                    error.message
                                );

                                Ok(())
                            }),
                    );
                    Ok(())
                },
            ));
        env.spawn(Box::new(watch_blocks.then(|r| {
            match r {
                // Block stream ended.
                Ok(Ok(())) => {
                    warn!("manager block stream ended");
                }
                // Manager dropped.
                Ok(Err(_ /* ekiden_core::futures::killable::Killed */)) => {}
                // Block stream errored.
                Err(e) => {
                    error!("manager block stream error: {}", e);
                }
            }
            Ok(())
        })));
        Self {
            commit_sub: commit_sub_2,
            blocks_kill_handle,
        }
    }

    /// Make a `Manager` from an injected `ConsensusBackend` and an injected `StorageBackend`.
    pub fn new_from_injected(contract_id: B256, container: &mut Container) -> Result<Self> {
        let env: Arc<Environment> = container.inject()?;
        let consensus: Arc<ConsensusBackend> = container.inject()?;
        let storage: Arc<StorageBackend> = container.inject()?;
        Ok(Self::new(
            env.as_ref(),
            contract_id,
            consensus.as_ref(),
            storage,
        ))
    }

    pub fn create_wait(&self) -> Wait {
        // Some calls from earlier blocks may come through too (e.g., if we are fetching the
        // inputs/outputs from storage when we subscribe). That won't break things though.
        // The subscription has an unbounded buffer for holding commit info maps, so that we can
        // hold on to a `Wait`, and the notifier doesn't have to block.
        let (_init, stockpile) = self.commit_sub.subscribe();
        Wait { stockpile }
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        self.blocks_kill_handle.kill();
    }
}
