//! Block watcher for efficient `get_latest_block`.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use futures::prelude::*;
use thiserror::Error;
use tokio::sync::watch;
use tokio_stream::wrappers::WatchStream;

use super::snapshot::BlockSnapshot;

/// Block watcher error.
#[derive(Error, Debug)]
pub enum WatchError {
    #[error("block stream closed")]
    BlockStreamClosed,
    #[error("block watcher closed")]
    WatcherClosed,
}

struct Inner {
    spawned: AtomicBool,
    current_block: watch::Receiver<Option<BlockSnapshot>>,
    current_block_tx: Mutex<Option<watch::Sender<Option<BlockSnapshot>>>>,
}

/// Block watcher.
#[derive(Clone)]
pub struct BlockWatcher {
    inner: Arc<Inner>,
}

impl BlockWatcher {
    /// Create new block watcher.
    pub fn new() -> Self {
        let (tx, rx) = watch::channel(None);

        Self {
            inner: Arc::new(Inner {
                spawned: AtomicBool::new(false),
                current_block: rx,
                current_block_tx: Mutex::new(Some(tx)),
            }),
        }
    }

    /// Atomically check if a new block watcher needs to be spawned and
    /// mark it as spawned/spawning. If this method returns true, then
    /// the caller must go ahead and call either `spawn` or `cancel_spawn`.
    pub fn start_spawn(&self) -> bool {
        !self
            .inner
            .spawned
            .compare_and_swap(false, true, Ordering::SeqCst)
    }

    /// Cancel a previous spawn started by `start_spawn`.
    pub fn cancel_spawn(&self) {
        assert!(
            self.inner.spawned.swap(false, Ordering::SeqCst),
            "must only be called in start_spawn"
        );
    }

    /// Spawn a block watcher task.
    ///
    /// Must only be called after first calling `start_spawn`.
    pub fn spawn<T>(&self, blocks: T)
    where
        T: Stream<Item = Result<BlockSnapshot, WatchError>> + Send + 'static,
    {
        let tx = self
            .inner
            .current_block_tx
            .lock()
            .unwrap()
            .take()
            .expect("must only be called in start_spawn");

        let inner = self.inner.clone();
        let mut blocks = Box::pin(blocks);
        tokio::spawn(async move {
            while let Some(Ok(blk)) = blocks.next().await {
                if let Err(_) = tx.send(Some(blk)) {
                    break;
                }
            }

            // Watch has terminated which indicates that there is something wrong
            // with the stream. Put the sender back so we can retry the watch.
            inner.current_block_tx.lock().unwrap().replace(tx);
            assert!(
                inner.spawned.swap(false, Ordering::SeqCst),
                "must only be called in start_spawn"
            );
        });
    }

    /// Get the latest block.
    pub async fn get_latest_block(&self) -> Result<BlockSnapshot, WatchError> {
        let rx = WatchStream::new(self.inner.current_block.clone());

        let blk = rx
            .skip_while(|blk| future::ready(blk.is_none()))
            .take(1)
            .into_future()
            .await
            .0
            .ok_or(WatchError::WatcherClosed)?
            .expect("None blocks were skipped");

        Ok(blk)
    }
}
