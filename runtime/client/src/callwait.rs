use std::{self, collections::HashMap, sync::Arc};

use serde_cbor;

use ekiden_common::{
    self,
    bytes::{B256, H256},
    environment::Environment,
    error::Error,
    futures::{BoxFuture, BoxStream, Future, Stream},
    hash::EncodedHash,
    subscribers::StreamSubscribers,
    uint::U256,
};
use ekiden_roothash_base::{backend::RootHashBackend, block::Block, header::HeaderType};
use ekiden_runtime_common::batch::{CallBatch, OutputBatch};
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
    /// We distribute commitment information here.
    commit_sub: Arc<StreamSubscribers<SharedCommitInfo>>,
    /// For distributing epoch transition notifications.
    epoch_transition_sub: Arc<StreamSubscribers<Block>>,
    /// For killing our root hash follower task.
    blocks_kill_handle: ekiden_common::futures::KillHandle,
}

impl Manager {
    pub fn new(
        env: Arc<Environment>,
        runtime_id: B256,
        roothash: Arc<RootHashBackend>,
        storage: Arc<StorageBackend>,
    ) -> Self {
        let commit_sub = Arc::new(StreamSubscribers::new());
        let commit_sub_blocks = commit_sub.clone();
        let epoch_transition_sub = Arc::new(StreamSubscribers::new());
        let epoch_transition_sub_blocks = epoch_transition_sub.clone();
        let roothash_init = roothash.clone();
        let (watch_blocks, blocks_kill_handle) = ekiden_common::futures::killable(
            ekiden_common::futures::streamfollow::follow(
                "callwait blocks",
                move || roothash_init.get_blocks(runtime_id),
                move |round: &U256| roothash.get_blocks_since(runtime_id, round.clone()),
                |block: &Block| block.header.round,
                // TODO: detect permanent errors?
                |_e| false,
            )
            .for_each(move |block: Block| {
                // Check if this is an epoch transition notification.
                if block.header.header_type == HeaderType::EpochTransition {
                    epoch_transition_sub_blocks.notify(&block);
                }

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
            }),
        );
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
            commit_sub,
            epoch_transition_sub,
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

    pub fn watch_epoch_transitions(&self) -> BoxStream<Block> {
        self.epoch_transition_sub.subscribe().1
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        self.blocks_kill_handle.kill();
    }
}
