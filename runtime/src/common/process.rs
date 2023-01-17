//! Process-related helpers.
use std::io::Write;

/// Aborts the process via `std::process::abort`, but also making sure that log buffers are flushed.
pub fn abort() -> ! {
    // Attempt to flush buffers to ensure any log output makes it.
    let _ = std::io::stderr().flush();
    let _ = std::io::stdout().flush();

    // Abort the process.
    std::process::abort()
}
