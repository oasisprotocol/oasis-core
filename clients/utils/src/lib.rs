#[cfg(feature = "benchmark")]
extern crate histogram;
#[cfg(feature = "benchmark")]
extern crate threadpool;
#[cfg(feature = "benchmark")]
extern crate time;

#[cfg(feature = "benchmark")]
pub mod benchmark;

#[macro_use]
mod macros;
