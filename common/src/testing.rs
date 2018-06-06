//! Testing utilities.
#[cfg(not(target_env = "sgx"))]
use std;

#[cfg(not(target_env = "sgx"))]
use env_logger::fmt::Target;
#[cfg(not(target_env = "sgx"))]
use log::LevelFilter;
#[cfg(not(target_env = "sgx"))]
use pretty_env_logger;

/// Attempt to initialize the global logger for `Trace` level logging,
/// outputting to stdout, iff the `--nocapture` command line argument is
/// passed to the test binary.
///
/// This call is idempotent, and failures are silently ignored.
#[cfg(not(target_env = "sgx"))]
pub fn try_init_logging() {
    // Rust/Cargo bugs prevent stdout from threads from being captured, so
    // manually inspect the command line arguments to see if log output
    // should be displayed.
    //
    // See: https://github.com/rust-lang/rust/issues/42474

    for arg in std::env::args() {
        if arg == "--nocapture" {
            let mut builder = match pretty_env_logger::formatted_builder() {
                Ok(builder) => builder,
                Err(_) => return,
            };

            let _ = builder
                .filter(None, LevelFilter::Trace)
                .target(Target::Stdout)
                .try_init();
            return;
        }
    }
}
