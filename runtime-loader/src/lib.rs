//! Oasis runtime loader.

#[cfg(target_os = "linux")]
pub mod sgxs;

use anyhow::Result;

/// Runtime loader.
pub trait Loader {
    /// Load and run the specified runtime.
    fn run(
        &self,
        filename: &str,
        signature_filename: Option<&str>,
        host_socket: &str,
    ) -> Result<()>;
}

// Re-exports.
#[cfg(target_os = "linux")]
pub use sgxs::SgxsLoader;
