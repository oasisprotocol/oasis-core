//! Oasis runtime loader.
extern crate aesm_client;
extern crate enclave_runner;
extern crate failure;
extern crate sgxs_loaders;

pub mod elf;
pub mod sgxs;

use failure::Fallible;

/// Runtime loader.
pub trait Loader {
    /// Load and run the specified runtime.
    fn run(&self, filename: String, host_socket: String) -> Fallible<()>;
}

// Re-exports.
pub use self::{elf::ElfLoader, sgxs::SgxsLoader};
