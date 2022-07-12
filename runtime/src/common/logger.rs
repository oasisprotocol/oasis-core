//! Logging subsystem for runtimes.
use std::sync::{Mutex, Once};

use lazy_static::lazy_static;
use log::Level;
use slog::{self, o, Drain};
use slog_scope;
use slog_stdlog;

lazy_static! {
    static ref LOGGER: slog::Logger = slog::Logger::root(
        Mutex::new(slog_json::Json::default(std::io::stderr())).map(slog::Fuse),
        o!()
    );

    /// Initializes the global logger once.
    static ref INIT_GLOBAL_LOGGER: Once = Once::new();

    /// Prevents the global logger from being dropped.
    static ref GLOBAL_LOGGER_SCOPE_GUARD: Mutex<Option<slog_scope::GlobalLoggerGuard>> = Mutex::new(None);
}

/// Get the logger.
pub fn get_logger(module: &'static str) -> slog::Logger {
    LOGGER.new(o!("module" => module))
}

/// Initialize the global slog_stdlog adapter to allow logging with the log crate (instead of slog).
pub fn init_logger(level: Level) {
    INIT_GLOBAL_LOGGER.call_once(|| {
        let global_logger = LOGGER.new(o!("module" => "global"));
        GLOBAL_LOGGER_SCOPE_GUARD
            .lock()
            .unwrap()
            .get_or_insert(slog_scope::set_global_logger(global_logger));
        slog_stdlog::init_with_level(level).unwrap();
    });
}
