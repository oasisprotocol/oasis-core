//! TDX-specific initialization.
use nix::{
    mount::{mount, MsFlags},
    sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal},
};
use slog::info;

use crate::common::logger::get_logger;

/// Perform TDX-specific early initialization.
pub fn init() {
    let logger = get_logger("runtime/tdx");

    // Mount required filesystems.
    info!(logger, "Mounting required filesystems");
    let _ = mount(
        None::<&str>,
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    );
    let _ = mount(
        None::<&str>,
        "/sys",
        Some("sysfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    );
    let _ = mount(
        None::<&str>,
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_NOSUID,
        None::<&str>,
    );
    let _ = mount(
        None::<&str>,
        "/sys/kernel/config",
        Some("configfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    );

    // Ignore SIGCHLD and let the kernel reap zombies.
    info!(logger, "Setting up signal handlers");
    unsafe {
        let _ = sigaction(
            Signal::SIGCHLD,
            &SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty()),
        );
    }

    info!(logger, "Early initialization completed");
}
