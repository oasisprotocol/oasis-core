//! Future types used in Ekiden.
extern crate futures as extern_futures;

pub use self::extern_futures::*;

use super::error::Error;

/// Future type for use in Ekiden.
pub type BoxFuture<T> = Box<Future<Item = T, Error = Error> + Send>;

/// Stream type for use in Ekiden.
pub type BoxStream<T> = Box<Stream<Item = T, Error = Error> + Send>;
