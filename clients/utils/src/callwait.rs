use std::collections::HashMap;
use std::sync::Arc;

use grpcio::Environment;

use ekiden_consensus_base::backend::ConsensusBackend;
use ekiden_consensus_base::block::Block;
use ekiden_core;
use ekiden_core::contract::batch::CallBatch;
use ekiden_core::contract::batch::OutputBatch;
use ekiden_core::futures::BoxFuture;
use ekiden_core::futures::BoxStream;
use ekiden_core::subscribers::StreamSubscribers;
use ekiden_storage_base::backend::StorageBackend;

type SharedCommitInfo = Arc<HashMap<H256, Vec<u8>>>;

pub struct Wait {
    stockpile: BoxStream<SharedCommitInfo>,
}

impl Wait {
    pub fn wait_for(self, call_id: H256) -> BoxFuture<Vec<u8>> {
        Box::new(
            self.stockpile
                .filter_map(|sci: SharedCommitInfo| sci.get(call_id).map(|output| output.clone()))
                .into_future()
                .and_then(|(item, _rest)| Ok(item)),
        )
    }
}

struct Manager {
    /// We distribute commitment information here.
    commit_sub: Arc<StreamSubscribers<SharedCommitInfo>>,
    /// For killing our consensus follower task.
    blocks_kill_handle: ekiden_core::futures::KillHandle,
}

impl Manager {
    pub fn new(
        env: Arc<Environment>,
        contract_id: B256,
        consensus: &ConsensusBackend,
        storage: Arc<StorageBackend>,
    ) -> Self {
        let commit_sub = Arc::new(StreamSubscribers::new());
        let commit_sub_2 = commit_sub.clone();
        let (watch_blocks, blocks_kill_handle) = ekiden_core::futures::killable(
            consensus
                .get_blocks(contract_id)
                .for_each(move |block: Block| {
                    if block.header.input_hash == ekiden_core::hash::empty_hash() {
                        return Ok(());
                    }

                    // Check if any subscribed transactions have been included in a block. To do that
                    // we need to fetch transactions from storage first. Do this in a separate task
                    // to not block command processing.
                    // This wastes local work and storage network effort if we aren't waiting for
                    // anything. We might be able to save this if we add functionality to
                    // `StreamSubscriber` to check if there are no subscriptions.
                    env.spawn(
                        storage
                            .get(block.header.input_hash)
                            .join(inner.storage.get(block.header.output_hash))
                            .and_then(move |(inputs, outputs)| {
                                let inputs: CallBatch = serde_cbor::from_slice(&inputs)?;
                                let outputs: OutputBatch = serde_cbor::from_slice(&outputs)?;
                                let mut commit_info = HashMap::with_capacity(inputs.len());

                                for (input, output) in inputs.iter().zip(outputs.into_iter()) {
                                    let call_id = input.get_encoded_hash();

                                    commit_info.insert(call_id, output);
                                }
                                commit_sub.notify(&Arc::new(commit_info));

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
                }),
        );
        env.spawn(Box::new(watch_blocks.then(|r| {
            match r {
                // Block stream ended.
                Ok(Ok(())) => {
                    warn!("manager block stream ended");
                }
                // Kill handle dropped.
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

    pub fn create_wait(&self) -> Wait {
        // Some calls from earlier blocks may come through too (e.g., if we are fetching the
        // inputs/outputs from storage when we subscribe). That's not a problem.
        let (_init, stockpile) = self.commit_sub.subscribe();
        Wait { stockpile }
    }
}
