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

/// Get the logger.
pub fn get_logger(module: &'static str) -> slog::Logger {
    LOGGER.new(o!("module" => module))
}
