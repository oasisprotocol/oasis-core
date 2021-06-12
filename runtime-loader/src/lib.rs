//! Oasis runtime loader.

pub mod elf;
#[cfg(target_os = "linux")]
pub mod sgxs;

use failure::Fallible;

/// Runtime loader.
pub trait Loader {
    /// Load and run the specified runtime.
    fn run(
        &self,
        filename: String,
        signature_filename: Option<&str>,
        host_socket: String,
    ) -> Fallible<()>;
}

// Re-exports.
pub use elf::ElfLoader;
#[cfg(target_os = "linux")]
pub use sgxs::SgxsLoader;
