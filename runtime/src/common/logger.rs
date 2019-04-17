//! Logging subsystem for runtimes.
use std::sync::Mutex;

use lazy_static::lazy_static;
use slog::{self, Drain};

lazy_static! {
    static ref LOGGER: slog::Logger = slog::Logger::root(
        Mutex::new(slog_json::Json::default(std::io::stderr())).map(slog::Fuse),
        o!()
    );
}

/// Init the log adapter.
pub fn init_logger() {
    let _scope_guard = slog_scope::set_global_logger(LOGGER.clone());
    let _log_guard = slog_stdlog::init_with_level(log::LogLevel::Trace).unwrap();
}

/// Get the logger.
pub fn get_logger(module: &'static str) -> slog::Logger {
    LOGGER.new(o!("module" => module))
}
