//! Block watcher for efficient `get_latest_block`.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use ekiden_runtime::common::roothash::Block;
use futures::{prelude::*, stream::Fuse, try_ready};
use tokio::{spawn, sync::watch};

/// Block watcher error.
#[derive(Debug, Fail)]
pub enum WatchError {
    #[fail(display = "block watcher closed")]
    WatcherClosed,
}

struct Inner {
    spawned: AtomicBool,
    current_block: watch::Receiver<Option<Block>>,
    current_block_tx: Mutex<Option<watch::Sender<Option<Block>>>>,
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
        T: Stream<Item = Option<Block>> + Send + 'static,
    {
        let tx = self
            .inner
            .current_block_tx
            .lock()
            .unwrap()
            .take()
            .expect("must only be called in start_spawn");

        let inner = self.inner.clone();
        spawn(
            Watch::new(blocks, tx)
                .map_err(|_err| ())
                .and_then(move |tx| {
                    // Watch has terminated which indicates that there is something wrong
                    // with the stream. Put the sender back so we can retry the watch.
                    inner.current_block_tx.lock().unwrap().replace(tx);
                    assert!(
                        inner.spawned.swap(false, Ordering::SeqCst),
                        "must only be called in start_spawn"
                    );
                    Ok(())
                }),
        );
    }

    /// Get the latest block.
    pub fn get_latest_block(&self) -> impl Future<Item = Block, Error = WatchError> {
        self.inner
            .current_block
            .clone()
            .skip_while(|block| Ok(block.is_none()))
            .take(1)
            .into_future()
            .map_err(|_err| WatchError::WatcherClosed)
            .and_then(|(maybe_block, _)| {
                Ok(maybe_block
                    .ok_or(WatchError::WatcherClosed)?
                    .expect("None blocks were skipped"))
            })
    }
}

struct Watch<T: Stream, U> {
    stream: Option<Fuse<T>>,
    sink: Option<U>,
    buffered: Option<T::Item>,
}

impl<T: Stream, U> Watch<T, U>
where
    U: Sink<SinkItem = T::Item>,
    T: Stream,
{
    pub fn new(stream: T, sink: U) -> Self {
        Self {
            stream: Some(stream.fuse()),
            sink: Some(sink),
            buffered: None,
        }
    }

    /// Get a mutable reference to the inner sink.
    /// If this combinator has already been polled to completion, None will be returned.
    pub fn sink_mut(&mut self) -> Option<&mut U> {
        self.sink.as_mut()
    }

    /// Get a mutable reference to the inner stream.
    /// If this combinator has already been polled to completion, None will be returned.
    pub fn stream_mut(&mut self) -> Option<&mut T> {
        self.stream.as_mut().map(|x| x.get_mut())
    }

    fn take_result(&mut self) -> U {
        let sink = self
            .sink
            .take()
            .expect("Attempted to poll Watch after completion");
        sink
    }

    fn try_start_send(&mut self, item: T::Item) -> Poll<(), U::SinkError> {
        debug_assert!(self.buffered.is_none());
        if let AsyncSink::NotReady(item) = self
            .sink_mut()
            .take()
            .expect("Attempted to poll Watch after completion")
            .start_send(item)?
        {
            self.buffered = Some(item);
            return Ok(Async::NotReady);
        }
        Ok(Async::Ready(()))
    }
}

impl<T: Stream, U> Future for Watch<T, U>
where
    U: Sink<SinkItem = T::Item>,
    T: Stream,
{
    type Item = U;
    type Error = U::SinkError;

    fn poll(&mut self) -> Poll<U, U::SinkError> {
        // If we've got an item buffered already, we need to write it to the
        // sink before we can do anything else.
        if let Some(item) = self.buffered.take() {
            try_ready!(self.try_start_send(item))
        }

        loop {
            match self
                .stream_mut()
                .take()
                .expect("Attempted to poll Watch after completion")
                .poll()
            {
                Ok(Async::Ready(Some(item))) => try_ready!(self.try_start_send(item)),
                Ok(Async::Ready(None)) => {
                    // Stream has completed, we return the sink without closing it.
                    return Ok(Async::Ready(self.take_result()));
                }
                Ok(Async::NotReady) => {
                    try_ready!(self
                        .sink_mut()
                        .take()
                        .expect("Attempted to poll Watch after completion")
                        .poll_complete());
                    return Ok(Async::NotReady);
                }
                Err(_) => {
                    // In case of an error with the stream, we return the sink without closing it.
                    return Ok(Async::Ready(self.take_result()));
                }
            }
        }
    }
}
