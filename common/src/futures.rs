//! Future types used in Ekiden.
extern crate futures as extern_futures;

pub use self::extern_futures::*;

use super::error::Error;

/// Future type for use in Ekiden.
pub type BoxFuture<T> = Box<Future<Item = T, Error = Error> + Send>;

/// Stream type for use in Ekiden.
pub type BoxStream<T> = Box<Stream<Item = T, Error = Error> + Send>;

/// Future trait with extra helper methods.
pub trait FutureExt: Future {
    #[cfg(target_env = "sgx")]
    fn wait(self) -> Result<Self::Item, Self::Error>
    where
        Self: Sized;

    /// Convenience function for turning this future into a trait object.
    fn into_box(self) -> Box<Future<Item = Self::Item, Error = Self::Error> + Send>
    where
        Self: Sized + Send + 'static,
    {
        Box::new(self)
    }

    /// Log errors produced by a future and discard them.
    fn log_errors_and_discard(
        self,
        log_target: &'static str,
        log_message: &'static str,
    ) -> Box<Future<Item = (), Error = ()> + Send>
    where
        Self: Sized + Send + 'static,
        Self::Error: ::std::fmt::Debug,
    {
        self.then(move |result| {
            if let Err(error) = result {
                warn!(target: log_target, "{}: {:?}", log_message, error);
            }

            future::ok(())
        }).into_box()
    }

    /// Discard item and error, returning a new future.
    fn discard(self) -> Box<Future<Item = (), Error = ()> + Send>
    where
        Self: Sized + Send + 'static,
    {
        self.map(|_| ()).map_err(|_| ()).into_box()
    }
}

impl<F: Future> FutureExt for F {
    #[cfg(target_env = "sgx")]
    fn wait(mut self) -> Result<Self::Item, Self::Error>
    where
        Self: Sized,
    {
        // Ekiden SGX enclaves are currently single-threaded and all OCALLs are blocking,
        // so nothing should return Async::NotReady.
        match self.poll() {
            Ok(Async::NotReady) => panic!("futures in SGX should always block"),
            Ok(Async::Ready(result)) => Ok(result),
            Err(error) => Err(error),
        }
    }
}

/// Stream trait with extra helper methods.
pub trait StreamExt: Stream {
    /// Convenience function for turning this stream into a trait object.
    fn into_box(self) -> Box<Stream<Item = Self::Item, Error = Self::Error> + Send>
    where
        Self: Sized + Send + 'static,
    {
        Box::new(self)
    }

    /// A wrapper for `for_each` which logs and discards all errors.
    ///
    /// This ensures that processing of the stream will continue even if errors are
    /// introduced.
    fn for_each_log_errors<F, U>(
        self,
        log_target: &'static str,
        log_message: &'static str,
        f: F,
    ) -> Box<Future<Item = (), Error = ()> + Send>
    where
        F: Fn(Self::Item) -> U + Send + 'static,
        U: FutureExt<Item = (), Error = Self::Error> + Send + 'static,
        Self: Sized + Send + 'static,
        Self::Error: ::std::fmt::Debug,
    {
        self.for_each(move |item| {
            f(item)
                .log_errors_and_discard(log_target, log_message)
                .map_err(|()| -> Self::Error {
                    unreachable!();
                })
        }).log_errors_and_discard(log_target, log_message)
    }
}

impl<S: Stream> StreamExt for S {}

/// Retry a future up to maximum number of retries.
///
/// The retry function is called on each retry to produce a future. If the future
/// resolves to an error, it is retried again unless the maximum number of retries
/// has been reached. In this case, the error itself is returned.
pub fn retry<F, R>(max_retries: usize, f: F) -> BoxFuture<R::Item>
where
    F: Fn() -> R + Send + 'static,
    R: Future + Send + 'static,
    R::Item: Send,
    R::Error: ::std::fmt::Display + Send,
{
    future::loop_fn(max_retries, move |retries| {
        f().and_then(|result| Ok(future::Loop::Break(result)))
            .or_else(move |error| {
                if retries == 0 {
                    return Err(Error::new(format!("{}", error)));
                }

                Ok(future::Loop::Continue(retries - 1))
            })
    }).into_box()
}

// Backported functionality from futures 0.3.
pub mod stream {
    use std::fmt::{self, Debug};

    pub use super::extern_futures::stream::*;
    use super::{Async, Poll, Stream};

    /// An unbounded set of streams
    ///
    /// This "combinator" provides the ability to maintain a set of streams
    /// and drive them all to completion.
    ///
    /// Streams are pushed into this set and their realized values are
    /// yielded as they become ready. Streams will only be polled when they
    /// generate notifications. This allows to coordinate a large number of streams.
    ///
    /// Note that you can create a ready-made `SelectAll` via the
    /// `select_all` function in the `stream` module, or you can start with an
    /// empty set with the `SelectAll::new` constructor.
    ///
    /// # Examples
    ///
    /// Starting with an empty set and populating it with streams:
    /// ```ignore
    /// let mut streams = stream::SelectAll::new();
    /// streams.push(stream_a.into_box());
    /// streams.push(stream_b.into_box());
    /// streams.for_each(|something| { /* ... */ });
    /// ```
    ///
    /// If streams return different items you may need to use `map` on each stream to
    /// map the items into a common time (e.g., an enumeration).
    #[must_use = "streams do nothing unless polled"]
    pub struct SelectAll<S> {
        inner: FuturesUnordered<StreamFuture<S>>,
    }

    impl<T: Debug> Debug for SelectAll<T> {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            write!(fmt, "SelectAll {{ ... }}")
        }
    }

    impl<S: Stream> SelectAll<S> {
        /// Constructs a new, empty `SelectAll`
        ///
        /// The returned `SelectAll` does not contain any streams and, in this
        /// state, `SelectAll::poll` will return `Ok(Async::Ready(None))`.
        pub fn new() -> SelectAll<S> {
            SelectAll {
                inner: FuturesUnordered::new(),
            }
        }

        /// Returns the number of streams contained in the set.
        ///
        /// This represents the total number of in-flight streams.
        pub fn len(&self) -> usize {
            self.inner.len()
        }

        /// Returns `true` if the set contains no streams
        pub fn is_empty(&self) -> bool {
            self.inner.is_empty()
        }

        /// Push a stream into the set.
        ///
        /// This function submits the given stream to the set for managing. This
        /// function will not call `poll` on the submitted stream. The caller must
        /// ensure that `SelectAll::poll` is called in order to receive task
        /// notifications.
        pub fn push(&mut self, stream: S) {
            self.inner.push(stream.into_future());
        }
    }

    impl<S: Stream> Stream for SelectAll<S> {
        type Item = S::Item;
        type Error = S::Error;

        fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
            match self.inner.poll().map_err(|(err, _)| err)? {
                Async::NotReady => Ok(Async::NotReady),
                Async::Ready(Some((Some(item), remaining))) => {
                    self.push(remaining);
                    Ok(Async::Ready(Some(item)))
                }
                Async::Ready(_) => Ok(Async::Ready(None)),
            }
        }
    }

    /// Convert a list of streams into a `Stream` of results from the streams.
    ///
    /// This essentially takes a list of streams (e.g. a vector, an iterator, etc.)
    /// and bundles them together into a single stream.
    /// The stream will yield items as they become available on the underlying
    /// streams internally, in the order they become available.
    ///
    /// Note that the returned set can also be used to dynamically push more
    /// futures into the set as they become available.
    pub fn select_all<I>(streams: I) -> SelectAll<I::Item>
    where
        I: IntoIterator,
        I::Item: Stream,
    {
        let mut set = SelectAll::new();

        for stream in streams {
            set.push(stream);
        }

        return set;
    }
}

/// Common futures-related exports.
///
/// Should be imported as follows:
/// ```ignore
/// use ekiden_common::futures::prelude::*;
/// ```
pub mod prelude {
    pub use super::{future, stream, BoxFuture, BoxStream, Future, FutureExt, Stream, StreamExt};
}
