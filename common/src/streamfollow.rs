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
    Polling,
    Connecting(Duration, S),
    Backoff(Duration, futures_timer::Delay),
    Forwarding(S),
}

pub struct Follow<S, B, FI, FR, FB, FP> {
    src_init: FI,
    src_resume: FR,
    item_to_bookmark: FB,
    error_is_permanent: FP,
    last: Option<B>,
    state: ConnectionState<S>,
}

impl<S, B, FI, FR, FB, FP> Follow<S, B, FI, FR, FB, FP>
where
    S: Stream,
    FI: Fn() -> S,
    FR: Fn(&B) -> S,
    FB: Fn(&S::Item) -> B,
    FP: Fn(&S::Error) -> bool,
{
    fn connect(&self) -> S {
        match self.last {
            None => (self.src_init)(),
            Some(ref bookmark) => (self.src_resume)(bookmark),
        }
    }
}

impl<S, B, FI, FR, FB, FP> Stream for Follow<S, B, FI, FR, FB, FP>
where
    S: Stream,
    FI: Fn() -> S,
    FR: Fn(&B) -> S,
    FB: Fn(&S::Item) -> B,
    FP: Fn(&S::Error) -> bool,
    B: Debug + PartialEq,
    S::Error: Debug,
{
    type Item = <S as Stream>::Item;
    type Error = <S as Stream>::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            match std::mem::replace(&mut self.state, ConnectionState::Polling) {
                ConnectionState::Polling => unreachable!(),
                ConnectionState::Connecting(backoff, mut stream) => {
                    match stream.poll() {
                        Ok(Async::Ready(None)) => {
                            error!("Underlying stream did not send current item");
                            return Ok(Async::Ready(None));
                        }
                        Ok(Async::Ready(Some(first))) => {
                            if let Some(ref bookmark) = self.last {
                                assert_eq!(bookmark, &(self.item_to_bookmark)(&first));
                            } else {
                                self.last = Some((self.item_to_bookmark)(&first));
                            }
                            self.state = ConnectionState::Forwarding(stream);
                            // Repeat poll on next state.
                        }
                        Ok(Async::NotReady) => {
                            self.state = ConnectionState::Connecting(backoff, stream);
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
                                self.state = ConnectionState::Backoff(
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
                            self.state = ConnectionState::Connecting(
                                backoff_advance(backoff),
                                self.connect(),
                            );
                            // Repeat poll on next state.
                        }
                        Async::NotReady => {
                            self.state = ConnectionState::Backoff(backoff, delay);
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
                            self.last = Some((self.item_to_bookmark)(&item));
                            self.state = ConnectionState::Forwarding(stream);
                            return Ok(Async::Ready(Some(item)));
                        }
                        Ok(Async::NotReady) => {
                            self.state = ConnectionState::Forwarding(stream);
                            return Ok(Async::NotReady);
                        }
                        Err(e) => {
                            if (self.error_is_permanent)(&e) {
                                return Err(e);
                            } else {
                                error!("Underlying stream error (late): {:?}; reconnecting", e);
                                self.state =
                                    ConnectionState::Connecting(backoff_init(), self.connect());
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
    src_init: FI,
    src_resume: FR,
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
    let state = ConnectionState::Connecting(backoff_init(), src_init());
    Follow {
        src_init,
        src_resume,
        item_to_bookmark,
        error_is_permanent,
        last: None,
        state,
    }
}
