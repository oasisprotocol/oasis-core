use std;
use std::collections::HashMap;
use std::sync::Arc;

use serde_cbor;

use ekiden_common;
use ekiden_common::bytes::B256;
use ekiden_common::bytes::H256;
use ekiden_common::environment::Environment;
use ekiden_common::error::Error;
use ekiden_common::futures::BoxFuture;
use ekiden_common::futures::BoxStream;
use ekiden_common::futures::Future;
use ekiden_common::futures::Stream;
use ekiden_common::hash::EncodedHash;
use ekiden_common::subscribers::StreamSubscribers;
use ekiden_contract_common::batch::CallBatch;
use ekiden_contract_common::batch::OutputBatch;
use ekiden_roothash_base::backend::RootHashBackend;
use ekiden_roothash_base::block::Block;
use ekiden_storage_base::backend::StorageBackend;

type SharedCommitInfo = Arc<HashMap<H256, Vec<u8>>>;

/// A temporary collection of incoming blocks, which you'll use when you need to wait for a call to
/// be committed, but you don't know the call ID yet.
pub struct Wait {
    stockpile: BoxStream<SharedCommitInfo>,
}

impl Wait {
    /// Call this when you know the call ID to wait for. You get a future that resolves with the
    /// call's output when it is committed.
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
    /// Keep the environment alive.
    _env: Arc<Environment>,
    /// Keep the root hash backend alive.
    _roothash: Arc<RootHashBackend>,
    /// We distribute commitment information here.
    commit_sub: Arc<StreamSubscribers<SharedCommitInfo>>,
    /// For killing our root hash follower task.
    blocks_kill_handle: ekiden_common::futures::KillHandle,
}

impl Manager {
    pub fn new(
        env: Arc<Environment>,
        contract_id: B256,
        roothash: Arc<RootHashBackend>,
        storage: Arc<StorageBackend>,
    ) -> Self {
        let commit_sub = Arc::new(StreamSubscribers::new());
        let commit_sub_blocks = commit_sub.clone();
        let (watch_blocks, blocks_kill_handle) =
            ekiden_common::futures::killable(roothash.get_blocks(contract_id).for_each(
                move |block: Block| {
                    if block.header.input_hash == ekiden_common::hash::empty_hash() {
                        return Ok(());
                    }

                    // Check what transactions are included in the block. To do that we need to
                    // fetch transactions from storage first.
                    // This wastes local work and storage network effort if we aren't waiting for
                    // anything. We might be able to save this if we add functionality to
                    // `StreamSubscriber` to check if there are no subscriptions.
                    let commit_sub_block = commit_sub_blocks.clone();
                    ekiden_common::futures::spawn(
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
                                commit_sub_block.notify(&Arc::new(commit_info));

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
            // TODO: propagate giveup-ness to waiting futures
            match r {
                // Block stream ended.
                Ok(Ok(())) => {
                    // The root hash system has ended the blockchain.
                    // For now, exit, because no more progress can be made.
                    error!("manager block stream ended");
                    std::process::exit(1);
                }
                // Manager dropped.
                Ok(Err(_ /* ekiden_common::futures::killable::Killed */)) => {}
                // Block stream errored.
                Err(e) => {
                    // Propagate error to service manager (high-velocity implementation).
                    error!("manager block stream error: {}", e);
                    std::process::exit(1);
                }
            };
            Ok(())
        })));
        Self {
            _env: env,
            _roothash: roothash,
            commit_sub,
            blocks_kill_handle,
        }
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
