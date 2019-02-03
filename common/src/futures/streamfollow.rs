use std::{
    self,
    fmt::Debug,
    time::{Duration, Instant},
};

use rand::{self, Rng};
use tokio;

use futures::{Async, Future, Poll, Stream};

struct Backoff {
    range_ms: u64,
}

impl Backoff {
    /// Choose the first duration to use when starting to back off.
    fn init() -> Self {
        Backoff { range_ms: 1000 }
    }

    /// Increase the backoff after a consecutive failure.
    fn advance(&mut self) {
        self.range_ms = std::cmp::min(self.range_ms * 2, 60_000);
    }

    /// Get a random duration from the current range.
    fn sample(&self) -> Duration {
        Duration::from_millis(rand::thread_rng().gen_range(50, self.range_ms))
    }
}

enum ConnectionState<S> {
    /// Dummy state for indicating a moved state or that we permanently errored/ended.
    Invalid,
    /// We've created a stream and we're waiting on the first/sentinel item to arrive. The
    /// `Backoff` is the range of time to wait before reconnecting if the stream errors
    /// nonpermanently.
    Connecting(Backoff, S),
    /// We're waiting before connecting again. The `Backoff` is the one *this* wait was sampled
    /// from.
    Backoff(Backoff, tokio::timer::Delay),
    /// We're waiting for more items from a stream to forward as our output.
    Forwarding(S),
}

/// A part of the logic of following a stream, including state that persists across reconnections
/// to the stream. Parameterized by the type of stream `S` being followed and a lightweight
/// "bookmark" type `B` for identifying items in the stream.
pub trait BookmarkState<S, B> {
    /// Create a stream for starting or resuming the stream, appropriate for the current state.
    fn connect(&mut self) -> S;
    /// Process the bookmark of the sentinel item from an input stream. Returns whether or not to
    /// forward the item to the output.
    fn check_first(&mut self, incoming_bookmark: B) -> bool;
    /// Process the bookmark of a non-sentinel item from an input stream.
    fn advance(&mut self, incoming_bookmark: B);
}

/// A `BookmarkState` implementation for streams that can be resumed from a specified item. Carries
/// functions "init" of type `FI` for opening the first stream and "resume" of type `FR` for
/// resuming from an item given its bookmark.
pub enum BookmarkStateResume<B, FI, FR> {
    /// Dummy state for indicating a moved state.
    Invalid,
    /// We're waiting for the first item.
    Initializing(FI, FR),
    /// We have received up to and including the item bookmarked by `self.1`.
    Anchored(FR, B),
}

impl<S, B, FI, FR> BookmarkState<S, B> for BookmarkStateResume<B, FI, FR>
where
    S: Stream,
    FI: FnMut() -> S,
    FR: FnMut(&B) -> S,
    B: PartialEq + Debug,
{
    /// Call init if we haven't seen anything yet or resume if we have a bookmark.
    fn connect(&mut self) -> S {
        match *self {
            BookmarkStateResume::Invalid => unreachable!(),
            BookmarkStateResume::Initializing(ref mut init, ref mut _resume) => init(),
            BookmarkStateResume::Anchored(ref mut resume, ref bookmark) => resume(bookmark),
        }
    }

    /// Transition to `Anchored` or check that the bookmark matches what we expect. Only forward
    /// the sentinel from the first stream.
    fn check_first(&mut self, incoming_bookmark: B) -> bool {
        match std::mem::replace(self, BookmarkStateResume::Invalid) {
            BookmarkStateResume::Invalid => unreachable!(),
            BookmarkStateResume::Initializing(_init, resume) => {
                *self = BookmarkStateResume::Anchored(resume, incoming_bookmark);
                true
            }
            BookmarkStateResume::Anchored(resume, bookmark) => {
                assert_eq!(incoming_bookmark, bookmark);
                *self = BookmarkStateResume::Anchored(resume, bookmark);
                false
            }
        }
    }

    /// Update the bookmark in an `Anchored` state.
    fn advance(&mut self, incoming_bookmark: B) {
        match std::mem::replace(self, BookmarkStateResume::Invalid) {
            BookmarkStateResume::Anchored(resume, _bookmark) => {
                *self = BookmarkStateResume::Anchored(resume, incoming_bookmark);
            }
            _ => unreachable!(),
        }
    }
}

/// A `BookmarkState` implementation for streams where it's okay to skip items that are missed
/// while reconnecting, i.e., where only the latest item is important. Carries function "init" of
/// type `FI` for opening streams.
pub enum BookmarkStateSkip<B, FI> {
    /// Dummy state for indicating a moved state.
    Invalid,
    /// We're waiting for the first item.
    Initializing(FI),
    /// We have received up to and including the item bookmarked by `self.1`.
    Anchored(FI, B),
}

impl<S, B, FI> BookmarkState<S, B> for BookmarkStateSkip<B, FI>
where
    S: Stream,
    FI: FnMut() -> S,
    B: PartialEq + Debug,
{
    /// Connect by calling the init fn.
    fn connect(&mut self) -> S {
        match *self {
            BookmarkStateSkip::Invalid => unreachable!(),
            BookmarkStateSkip::Initializing(ref mut init) => init(),
            BookmarkStateSkip::Anchored(ref mut init, ref _bookmark) => init(),
        }
    }

    /// Transition to `Anchored` and forward the sentinel, unless we're reconnecting and the
    /// bookmark is the same.
    fn check_first(&mut self, incoming_bookmark: B) -> bool {
        match std::mem::replace(self, BookmarkStateSkip::Invalid) {
            BookmarkStateSkip::Invalid => unreachable!(),
            BookmarkStateSkip::Initializing(init) => {
                *self = BookmarkStateSkip::Anchored(init, incoming_bookmark);
                true
            }
            BookmarkStateSkip::Anchored(init, bookmark) => {
                let forward_sentinel = incoming_bookmark != bookmark;
                *self = BookmarkStateSkip::Anchored(init, bookmark);
                // If the stream has moved on since we were last connected, forward the sentinel
                // item from this stream.
                forward_sentinel
            }
        }
    }

    /// Update the bookmark in a `Anchored` state.
    fn advance(&mut self, incoming_bookmark: B) {
        match std::mem::replace(self, BookmarkStateSkip::Invalid) {
            BookmarkStateSkip::Anchored(init, _bookmark) => {
                *self = BookmarkStateSkip::Anchored(init, incoming_bookmark);
            }
            _ => unreachable!(),
        }
    }
}

/// A wrapper for streams that can encounter nonpermanent errors. It handles the retry logic.
/// This is created by the `follow` function.
pub struct Follow<S, BS, FB, FP> {
    name: &'static str,
    connection_state: ConnectionState<S>,
    bookmark_state: BS,
    item_to_bookmark: FB,
    error_is_permanent: FP,
}

impl<S, B, BS, FB, FP> Stream for Follow<S, BS, FB, FP>
where
    S: Stream,
    BS: BookmarkState<S, B>,
    FB: Fn(&S::Item) -> B,
    FP: Fn(&S::Error) -> bool,
    B: PartialEq + Debug,
    S::Error: Debug,
{
    type Item = <S as Stream>::Item;
    type Error = <S as Stream>::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // Ensure that we are executing inside a Tokio runtime context which has a timer
        // context running. Otherwise this could fail later when attempting to retry, but
        // we want to catch failures early. This check is only performed in debug mode.
        #[cfg(debug_assertions)]
        tokio::timer::Delay::new(Instant::now())
            .poll()
            .expect("streamfollow task must be spawned in tokio runtime");

        loop {
            match std::mem::replace(&mut self.connection_state, ConnectionState::Invalid) {
                ConnectionState::Invalid => unreachable!(),
                ConnectionState::Connecting(backoff, mut stream) => {
                    match stream.poll() {
                        Ok(Async::Ready(None)) => {
                            error!("{} Underlying stream did not send current item", self.name);
                            return Ok(Async::Ready(None));
                        }
                        Ok(Async::Ready(Some(first))) => {
                            let bookmark = (self.item_to_bookmark)(&first);
                            debug!("{} Received sentinel item {:?}", self.name, bookmark);
                            let forward_sentinel = self.bookmark_state.check_first(bookmark);
                            self.connection_state = ConnectionState::Forwarding(stream);
                            if forward_sentinel {
                                trace!("{} Forwarding sentinel item", self.name);
                                return Ok(Async::Ready(Some(first)));
                            }
                            // Otherwise, discard sentinel (already emitted from previous stream)
                            // and repeat poll on next state.
                        }
                        Ok(Async::NotReady) => {
                            // Stay in connecting state. (We moved and destructured our state, so
                            // we have to put it back.)
                            self.connection_state = ConnectionState::Connecting(backoff, stream);
                            return Ok(Async::NotReady);
                        }
                        Err(e) => {
                            if (self.error_is_permanent)(&e) {
                                return Err(e);
                            } else {
                                let sample = backoff.sample();
                                error!(
                                    "{} Underlying stream error (early): {:?}; retrying in {:?}",
                                    self.name, e, sample
                                );
                                self.connection_state = ConnectionState::Backoff(
                                    backoff,
                                    tokio::timer::Delay::new(Instant::now() + sample),
                                );
                                // Repeat poll on next state.
                            }
                        }
                    }
                }
                ConnectionState::Backoff(mut backoff, mut delay) => {
                    match delay.poll().expect("Unhandled timer error") {
                        Async::Ready(()) => {
                            backoff.advance();
                            debug!("{} Connecting", self.name);
                            self.connection_state =
                                ConnectionState::Connecting(backoff, self.bookmark_state.connect());
                            // Repeat poll on next state.
                        }
                        Async::NotReady => {
                            // Stay in backoff state.
                            self.connection_state = ConnectionState::Backoff(backoff, delay);
                            return Ok(Async::NotReady);
                        }
                    }
                }
                ConnectionState::Forwarding(mut stream) => {
                    match stream.poll() {
                        Ok(Async::Ready(None)) => {
                            trace!("{} Underlying stream ended", self.name);
                            return Ok(Async::Ready(None));
                        }
                        Ok(Async::Ready(Some(item))) => {
                            let bookmark = (self.item_to_bookmark)(&item);
                            trace!("{} Forwarding item {:?}", self.name, bookmark);
                            // Stay in forwarding state.
                            self.connection_state = ConnectionState::Forwarding(stream);
                            self.bookmark_state.advance(bookmark);
                            return Ok(Async::Ready(Some(item)));
                        }
                        Ok(Async::NotReady) => {
                            // Stay in forwarding state.
                            self.connection_state = ConnectionState::Forwarding(stream);
                            return Ok(Async::NotReady);
                        }
                        Err(e) => {
                            if (self.error_is_permanent)(&e) {
                                return Err(e);
                            } else {
                                error!(
                                    "{} Underlying stream error (late): {:?}; reconnecting",
                                    self.name, e
                                );
                                self.connection_state = ConnectionState::Connecting(
                                    Backoff::init(),
                                    self.bookmark_state.connect(),
                                );
                                // Repeat poll on next state.
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Creates a stream and resume it if the stream errors nonpermanently.
///
/// Uses `init` to start the first stream (may be called multiple time if the stream errors) and
/// `resume` to start subsequent streams from the last received item. Streams should start with a
/// sentinel item: anything in `init`'s stream or a specified item in `resume`'s stream.
///
/// `resume` takes a specification of which item in the form of a "bookmark," obtained by applying
/// `item_to_bookmark` on an item.
///
/// Retries `init`/`resume` when an error is encountered, unless the error is "permanent," as
/// determined by `error_is_permanent`. Propagates permanent errors and `None` values to the
/// resulting stream.
///
/// Consecutive retries without receiving a sentinel item are delayed according to a hardcoded
/// backoff policy.
pub fn follow<S, B, FI, FR, FB, FP>(
    name: &'static str,
    mut init: FI,
    resume: FR,
    item_to_bookmark: FB,
    error_is_permanent: FP,
) -> Follow<S, BookmarkStateResume<B, FI, FR>, FB, FP>
where
    S: Stream,
    FI: FnMut() -> S,
    FR: FnMut(&B) -> S,
    FB: Fn(&S::Item) -> B,
    FP: Fn(&S::Error) -> bool,
{
    let connection_state = ConnectionState::Connecting(Backoff::init(), init());
    let bookmark_state = BookmarkStateResume::Initializing(init, resume);
    Follow {
        name,
        connection_state,
        bookmark_state,
        item_to_bookmark,
        error_is_permanent,
    }
}

/// Creates a stream and reconnect it if the stream errors nonpermanently. Compared to `follow`,
/// this combinator adapts streams that cannot be resumed from an arbitrary point. Skips any items
/// that would have been delivered while reconnecting.
///
/// Uses `init` to start the stream. Streams should start with a sentinel item: the latest item
/// that would have been sent if subscribed earlier.
///
/// Deduplicates the last received item from a stream and the sentinel item from the next stream by
/// comparing their "bookmarks," obtained by applying `item_to_bookmark` on the items.
///
/// Retries `init` when an error is encountered, unless the error is "permanent," as determined by
/// `error_is_permanent`. Propagates permanent errors and `None` values to the resulting stream.
///
/// Consecutive retries without receiving a sentinel item are delayed according to a hardcoded
/// backoff policy.
pub fn follow_skip<S, B, FI, FB, FP>(
    name: &'static str,
    mut init: FI,
    item_to_bookmark: FB,
    error_is_permanent: FP,
) -> Follow<S, BookmarkStateSkip<B, FI>, FB, FP>
where
    S: Stream,
    FI: FnMut() -> S,
    FB: Fn(&S::Item) -> B,
    FP: Fn(&S::Error) -> bool,
{
    let connection_state = ConnectionState::Connecting(Backoff::init(), init());
    let bookmark_state = BookmarkStateSkip::Initializing(init);
    Follow {
        name,
        connection_state,
        bookmark_state,
        item_to_bookmark,
        error_is_permanent,
    }
}

#[cfg(test)]
mod tests {
    use futures::{self, Stream};
    use tokio;

    #[test]
    fn follow_ok() {
        let s = super::follow(
            "follow_ok",
            || futures::stream::iter_result(vec![Ok(1), Ok(2), Ok(3)]),
            |&()| unreachable!(),
            |_| (),
            |&()| unreachable!(),
        );
        assert_eq!(
            tokio::runtime::current_thread::Runtime::new()
                .unwrap()
                .block_on(s.collect())
                .unwrap(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn follow_reconnect() {
        let mut inits = vec![vec![Err(())], vec![Ok(1), Ok(2), Err(())]].into_iter();
        let mut resumes = vec![vec![Err(())], vec![Ok(2), Err(())], vec![Ok(2), Ok(3)]].into_iter();
        let s = super::follow(
            "follow_reconnect",
            move || futures::stream::iter_result(inits.next().unwrap()),
            move |&()| futures::stream::iter_result(resumes.next().unwrap()),
            |_| (),
            |&()| false,
        );
        assert_eq!(
            tokio::runtime::current_thread::Runtime::new()
                .unwrap()
                .block_on(s.collect())
                .unwrap(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn follow_skip() {
        let mut inits = vec![
            vec![Err(())],
            vec![Ok(1), Ok(2), Err(())],
            vec![Err(())],
            vec![Ok(2), Err(())],
            vec![Ok(2), Ok(3), Err(())],
            vec![Ok(5)],
        ]
        .into_iter();
        let s = super::follow_skip(
            "follow_skip",
            move || futures::stream::iter_result(inits.next().unwrap()),
            |v| *v,
            |&()| false,
        );
        assert_eq!(
            tokio::runtime::current_thread::Runtime::new()
                .unwrap()
                .block_on(s.collect())
                .unwrap(),
            vec![1, 2, 3, 5]
        );
    }
}
