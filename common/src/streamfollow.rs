use std;
use std::fmt::Debug;
use std::time::Duration;

use futures_timer;

use futures::Async;
use futures::Future;
use futures::Poll;
use futures::Stream;

fn backoff_init() -> Duration {
    // TODO: I hear it's better to be random so multiple instances don't all retry at once.
    Duration::from_millis(1000)
}

fn backoff_advance(prev: Duration) -> Duration {
    std::cmp::min(prev * 2, Duration::from_secs(60))
}

enum ConnectionState<S> {
    Invalid,
    Connecting(Duration, S),
    Backoff(Duration, futures_timer::Delay),
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
    FI: Fn() -> S,
    FR: Fn(&B) -> S,
    B: PartialEq + Debug,
{
    fn connect(&self) -> S {
        match *self {
            BookmarkState::Invalid => unreachable!(),
            BookmarkState::Initializing(ref init, ref _resume) => init(),
            BookmarkState::Anchored(ref resume, ref bookmark) => resume(bookmark),
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
    FI: Fn() -> S,
    FR: Fn(&B) -> S,
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

pub fn follow<S, B, FI, FR, FB, FP>(
    init: FI,
    resume: FR,
    item_to_bookmark: FB,
    error_is_permanent: FP,
) -> Follow<S, B, FI, FR, FB, FP>
where
    S: Stream,
    FI: Fn() -> S,
    FR: Fn(&B) -> S,
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
