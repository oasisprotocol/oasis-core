use std;
use std::fmt::Debug;
use std::time::Duration;
use std::time::Instant;

use rand;
use rand::Rng;
use tokio;

use futures::Async;
use futures::Future;
use futures::Poll;
use futures::Stream;

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

enum BookmarkState<B, FI, FR> {
    /// Dummy state for indicating a moved state.
    Invalid,
    /// We're waiting for the first item.
    Initializing(FI, FR),
    /// We have received up to and including the item bookmarked by `self.1`.
    Anchored(FR, B),
}

impl<S, B, FI, FR> BookmarkState<B, FI, FR>
where
    S: Stream,
    FI: FnMut() -> S,
    FR: FnMut(&B) -> S,
    B: PartialEq + Debug,
{
    /// Create a stream appropriate for the bookmark state: init if we haven't seen anything yet,
    /// or resume if we have a bookmark.
    fn connect(&mut self) -> S {
        match *self {
            BookmarkState::Invalid => unreachable!(),
            BookmarkState::Initializing(ref mut init, ref mut _resume) => init(),
            BookmarkState::Anchored(ref mut resume, ref bookmark) => resume(bookmark),
        }
    }

    /// Process the sentinel item from an underlying stream: transition to
    /// `BookmarkState::Anchored` or check that the bookmark matches what we expect.
    fn offer_first(&mut self, b: B) {
        match std::mem::replace(self, BookmarkState::Invalid) {
            BookmarkState::Invalid => unreachable!(),
            BookmarkState::Initializing(_init, resume) => {
                *self = BookmarkState::Anchored(resume, b);
            }
            BookmarkState::Anchored(resume, bookmark) => {
                assert_eq!(b, bookmark);
                *self = BookmarkState::Anchored(resume, bookmark);
            }
        }
    }

    /// Update the bookmark in a `BookmarkState::Anchored` state.
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

/// A wrapper for streams that can encounter nonpermanent errors. It handles the retry logic.
/// This is created by the `follow` function.
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
                                    "Underlying stream error (early): {:?}; retrying in {:?}",
                                    e, sample
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
                            trace!("Underlying stream ended");
                            return Ok(Async::Ready(None));
                        }
                        Ok(Async::Ready(Some(item))) => {
                            // Stay in forwarding state.
                            self.connection_state = ConnectionState::Forwarding(stream);
                            self.bookmark_state.advance((self.item_to_bookmark)(&item));
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
                                error!("Underlying stream error (late): {:?}; reconnecting", e);
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
    let connection_state = ConnectionState::Connecting(Backoff::init(), init());
    let bookmark_state = BookmarkState::Initializing(init, resume);
    Follow {
        connection_state,
        bookmark_state,
        item_to_bookmark,
        error_is_permanent,
    }
}

#[cfg(test)]
mod tests {
    use futures;
    use futures::Future;
    use futures::Stream;
    use tokio;

    #[test]
    fn follow_ok() {
        let s = super::follow(
            || futures::stream::iter_result(vec![Ok(1), Ok(2), Ok(3)]),
            |&()| unreachable!(),
            |_| (),
            |&()| unreachable!(),
        );
        tokio::run(s.collect().then(|r| {
            assert_eq!(r.unwrap(), vec![1, 2, 3]);
            Ok(())
        }));
    }

    #[test]
    fn follow_reconnect() {
        let mut inits = vec![vec![Err(())], vec![Ok(1), Ok(2), Err(())]].into_iter();
        let mut resumes = vec![vec![Err(())], vec![Ok(2), Err(())], vec![Ok(2), Ok(3)]].into_iter();
        let s = super::follow(
            move || futures::stream::iter_result(inits.next().unwrap()),
            move |&()| futures::stream::iter_result(resumes.next().unwrap()),
            |_| (),
            |&()| false,
        );
        tokio::run(s.collect().then(|r| {
            assert_eq!(r.unwrap(), vec![1, 2, 3]);
            Ok(())
        }));
    }
}
