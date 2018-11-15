extern crate protobuf;
extern crate serde;
#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate ekiden_core;

#[macro_use]
mod api;
mod generated;

pub use generated::api::*;

use ekiden_core::bytes::B256;

/// Value wrapped together with a unique identifier.
///
/// This structure is used to wrap requests in order to ensure that each
/// request is unique as the simple token runtime doesn't have a notion
/// of nonces.
#[derive(Clone, Serialize, Deserialize)]
pub struct Unique<T>(pub T, pub B256);

impl<T> From<T> for Unique<T> {
    fn from(value: T) -> Self {
        Unique(value, B256::random())
    }
}
