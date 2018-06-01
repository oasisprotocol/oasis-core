use std::boxed::FnBox;
use std::thread;

use futures;
use futures::Future;
use futures::Stream;

// TODO: When boxed and unboxed FnOnce can be handled using common
// code, we won't need this custom trait anymore.
trait FactoryOnce<T> {
    fn build(self) -> T;
}

impl<T> FactoryOnce<T> for Box<FnBox() -> T + Send> {
    fn build(self) -> T {
        self()
    }
}

/// A `poll` implementation that receives future factories from a
/// stream, builds `Future`s, and polls them. Vaguely related to
/// `futures::stream::BufferUnordered`, but with the extra factory
/// business, without outputs, and where we haven't implemented
/// bounds.
struct Exec<S, F> {
    /// A stream for us to receive future factories.
    src: futures::stream::Fuse<S>,
    /// A list of Futures that we're executing.
    running: Vec<F>,
}

impl<S, F> Exec<S, F>
where
    S: futures::Stream,
{
    fn new(src: S) -> Self {
        Self {
            src: src.fuse(),
            running: vec![],
        }
    }
}

impl<S, F> futures::Future for Exec<S, F>
where
    S: futures::Stream,
    S::Item: FactoryOnce<F>,
    F: futures::Future<Item = (), Error = ()>,
{
    type Item = ();
    type Error = S::Error;

    fn poll(&mut self) -> futures::Poll<(), S::Error> {
        // Receive future factories from channel.
        loop {
            match self.src.poll() {
                Ok(futures::Async::Ready(Some(factory))) => {
                    // Got a future factory. Create the future and put it in our list.
                    self.running.push(factory.build());
                }
                Ok(futures::Async::Ready(None)) => {
                    // Stream ended, so there's nothing left to receive. Move on to next step.
                    break;
                }
                Ok(futures::Async::NotReady) => {
                    // Done receiving what's available. Move on to the next step.
                    break;
                }
                Err(e) => {
                    // Channel broke. Bail immediately.
                    return Err(e);
                }
            }
        }
        // Poll the futures that we're executing.
        self.running.drain_filter(|f| {
            match f.poll() {
                // Finished. Drain it.
                Ok(futures::Async::Ready(())) => true,
                // Still executing. Leave it.
                Ok(futures::Async::NotReady) => false,
                // Failed. Drain it silently. The futures given to us should propagate errors internally.
                Err(()) => true,
            }
        });
        if self.src.is_done() && self.running.is_empty() {
            // No more future factories, no more futures to execute. We're done!
            Ok(futures::Async::Ready(()))
        } else {
            // Wait for more future factories and execution progress.
            Ok(futures::Async::NotReady)
        }
    }
}

type BoxedVoidFuture = Box<futures::Future<Item = (), Error = ()>>;
type ProxyFactory = Box<FnBox() -> BoxedVoidFuture + Send>;

pub struct BoxyRemote {
    factory_tx: futures::sync::mpsc::UnboundedSender<ProxyFactory>,
}

impl BoxyRemote {
    pub fn spawn() -> BoxyRemote {
        let (factory_tx, factory_rx) = futures::sync::mpsc::unbounded();
        thread::spawn(move || {
            Exec::new(factory_rx).wait().unwrap();
        });
        BoxyRemote { factory_tx }
    }

    pub fn proxy<F, Fu, I, E>(&self, f: F) -> impl futures::Future<Item = I, Error = E>
    where
        F: FnOnce() -> Fu + Send + 'static,
        Fu: futures::Future<Item = I, Error = E> + 'static,
        I: Send + 'static,
        E: Send + 'static,
    {
        let (result_tx, result_rx) = futures::sync::oneshot::channel();
        self.factory_tx
            .unbounded_send(Box::new(move || {
                Box::new(f().then(|result| {
                    // Don't mind if initiator hung up.
                    drop(result_tx.send(result));
                    Ok(())
                })) as BoxedVoidFuture
            }) as ProxyFactory)
            .unwrap();
        result_rx.then(|result| result.unwrap())
    }
}

#[test]
fn round_trip() {
    let r = BoxyRemote::spawn();
    r.proxy(|| futures::future::ok::<i32, i32>(9))
        .and_then(|v| {
            assert_eq!(v, 9);
            Ok(())
        })
        .wait()
        .unwrap();
}
