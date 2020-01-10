extern crate serde;
extern crate serde_derive;

extern crate oasis_core_runtime;

#[macro_use]
mod api;

pub use api::WorkerInfo;
pub use api::JobSubmission;
