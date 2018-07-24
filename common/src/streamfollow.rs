use std;
use std::fmt::Debug;
use std::time::Duration;

use futures_timer;

use futures::Async;
use futures::Future;
use futures::Poll;
use futures::Stream;

/// Choose the first duration to use when starting to back off.
fn backoff_init() -> Duration {
    // TODO: I hear it's better to be random so multiple instances don't all retry at once.
    Duration::from_millis(1000)
}

/// Choose the next duration to use when backing off.
fn backoff_advance(prev: Duration) -> Duration {
    std::cmp::min(prev * 2, Duration::from_secs(60))
}

enum ConnectionState<S> {
    /// Dummy state for indicating a moved state or that we permanently errored/ended.
    Invalid,
    /// We've created a stream and we're waiting on the first element/sentinel item to arrive. The
    /// `Duration` is the amount of time to wait before reconnecting if the stream errors
    /// nonpermanently.
    Connecting(Duration, S),
    /// We're waiting before connecting again. The `Duration` is how long *this* wait is.
    Backoff(Duration, futures_timer::Delay),
    /// We're waiting for more items from a stream to forward as our output.
    Forwarding(S),
}

enum BookmarkState<B, FI, FR> {
    Invalid,
    Initializing(FI, FR),
    Anchored(FR, B),
}

impl<S, B, FI, FR> BookmarkState<B, FI, FR>
where
    S: Stream,
    FI: FnMut() -> S,
    FR: FnMut(&B) -> S,
    B: PartialEq + Debug,
{
    fn connect(&mut self) -> S {
        match *self {
            BookmarkState::Invalid => unreachable!(),
            BookmarkState::Initializing(ref mut init, ref mut _resume) => init(),
            BookmarkState::Anchored(ref mut resume, ref bookmark) => resume(bookmark),
        }
    }

    fn offer_first(&mut self, b: B) {
        match std::mem::replace(self, BookmarkState::Invalid) {
            BookmarkState::Invalid => unreachable!(),
            BookmarkState::Initializing(_init, resume) => {
                *self = BookmarkState::Anchored(resume, b);
            }
            BookmarkState::Anchored(_resume, bookmark) => {
                assert_eq!(b, bookmark);
            }
        }
    }

    fn advance(&mut self, b: B) {
        match std::mem::replace(self, BookmarkState::Invalid) {
            BookmarkState::Anchored(resume, _bookmark) => {
                *self = BookmarkState::Anchored(resume, b);
            }
            _ => unreachable!(),
        }
    }
}

pub struct Follow<S, B, FI, FR, FB, FP> {
    connection_state: ConnectionState<S>,
    bookmark_state: BookmarkState<B, FI, FR>,
    item_to_bookmark: FB,
    error_is_permanent: FP,
}

impl<S, B, FI, FR, FB, FP> Stream for Follow<S, B, FI, FR, FB, FP>
where
    S: Stream,
    FI: FnMut() -> S,
    FR: FnMut(&B) -> S,
    FB: Fn(&S::Item) -> B,
    FP: Fn(&S::Error) -> bool,
    B: PartialEq + Debug,
    S::Error: Debug,
{
    type Item = <S as Stream>::Item;
    type Error = <S as Stream>::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            match std::mem::replace(&mut self.connection_state, ConnectionState::Invalid) {
                ConnectionState::Invalid => unreachable!(),
                ConnectionState::Connecting(backoff, mut stream) => {
                    match stream.poll() {
                        Ok(Async::Ready(None)) => {
                            error!("Underlying stream did not send current item");
                            return Ok(Async::Ready(None));
                        }
                        Ok(Async::Ready(Some(first))) => {
                            self.bookmark_state
                                .offer_first((self.item_to_bookmark)(&first));
                            self.connection_state = ConnectionState::Forwarding(stream);
                            return Ok(Async::Ready(Some(first)));
                        }
                        Ok(Async::NotReady) => {
                            self.connection_state = ConnectionState::Connecting(backoff, stream);
                            return Ok(Async::NotReady);
                        }
                        Err(e) => {
                            if (self.error_is_permanent)(&e) {
                                return Err(e);
                            } else {
                                error!(
                                    "Underlying stream error (early): {:?}; retrying in {:?}",
                                    e, backoff
                                );
                                self.connection_state = ConnectionState::Backoff(
                                    backoff,
                                    futures_timer::Delay::new(backoff),
                                );
                                // Repeat poll on next state.
                            }
                        }
                    }
                }
                ConnectionState::Backoff(backoff, mut delay) => {
                    match delay.poll().expect("Unhandled timer error") {
                        Async::Ready(()) => {
                            self.connection_state = ConnectionState::Connecting(
                                backoff_advance(backoff),
                                self.bookmark_state.connect(),
                            );
                            // Repeat poll on next state.
                        }
                        Async::NotReady => {
                            self.connection_state = ConnectionState::Backoff(backoff, delay);
                            return Ok(Async::NotReady);
                        }
                    }
                }
                ConnectionState::Forwarding(mut stream) => {
                    match stream.poll() {
                        Ok(Async::Ready(None)) => {
                            trace!("Underlying stream ended");
                            return Ok(Async::Ready(None));
                        }
                        Ok(Async::Ready(Some(item))) => {
                            self.connection_state = ConnectionState::Forwarding(stream);
                            self.bookmark_state.advance((self.item_to_bookmark)(&item));
                            return Ok(Async::Ready(Some(item)));
                        }
                        Ok(Async::NotReady) => {
                            self.connection_state = ConnectionState::Forwarding(stream);
                            return Ok(Async::NotReady);
                        }
                        Err(e) => {
                            if (self.error_is_permanent)(&e) {
                                return Err(e);
                            } else {
                                error!("Underlying stream error (late): {:?}; reconnecting", e);
                                self.connection_state = ConnectionState::Connecting(
                                    backoff_init(),
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
/// sentinel item: anything in `init`'s stream or a specified item in `resume`'s stream. `resume`
/// takes a specification of which item in the form of a "bookmark," obtained by applying
/// `item_to_bookmark` on an item. Retries `init`/`resume` when an error is encountered, unless
/// the error is "permanent," as determined by `error_is_permanent`. Propagates permanent errors
/// and `None` values to the resulting stream. Consecutive retries without receiving a sentinel
/// item are delayed according to a hardcoded backoff policy.
pub fn follow<S, B, FI, FR, FB, FP>(
    mut init: FI,
    resume: FR,
    item_to_bookmark: FB,
    error_is_permanent: FP,
) -> Follow<S, B, FI, FR, FB, FP>
where
    S: Stream,
    FI: FnMut() -> S,
    FR: FnMut(&B) -> S,
    FB: Fn(&S::Item) -> B,
    FP: Fn(&S::Error) -> bool,
{
    let connection_state = ConnectionState::Connecting(backoff_init(), init());
    let bookmark_state = BookmarkState::Initializing(init, resume);
    Follow {
        connection_state,
        bookmark_state,
        item_to_bookmark,
        error_is_permanent,
    }
}
