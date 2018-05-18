#[cfg(feature = "benchmark")]
extern crate histogram;
#[cfg(feature = "benchmark")]
extern crate threadpool;
#[cfg(feature = "benchmark")]
extern crate time;

#[cfg(feature = "benchmark")]
pub mod benchmark;

#[doc(hidden)]
#[macro_use]
pub mod macros;
