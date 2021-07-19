//! Runtime initialization.
use std::{env, sync::Arc};

use log;
use slog::{error, info};

use crate::{
    common::{
        logger::{get_logger, init_logger},
        version::Version,
    },
    dispatcher::{Dispatcher, Initializer},
    protocol::{Protocol, Stream},
    rak::RAK,
};

/// Starts the runtime.
pub fn start_runtime(initializer: Box<dyn Initializer>, version: Version) {
    // Output backtraces.
    env::set_var("RUST_BACKTRACE", "1");

    // Initialize logging.
    init_logger(log::Level::Info);
    let logger = get_logger("runtime");
    info!(logger, "Runtime is starting");

    // Initialize runtime attestation key.
    let rak = Arc::new(RAK::new());

    // Initialize the dispatcher.
    let dispatcher = Dispatcher::new(initializer, rak.clone());

    info!(logger, "Establishing connection with the worker host");

    #[cfg(not(target_env = "sgx"))]
    let stream = match Stream::connect(env::var("OASIS_WORKER_HOST").unwrap_or_default()) {
        Err(error) => {
            error!(logger, "Failed to connect with the worker host"; "err" => %error);
            return;
        }
        Ok(stream) => stream,
    };

    #[cfg(target_env = "sgx")]
    let stream = match Stream::connect("worker-host") {
        Err(error) => {
            error!(logger, "Failed to connect with the worker host"; "err" => %error);
            return;
        }
        Ok(stream) => stream,
    };

    // Start handling protocol messages. This blocks the main thread forever
    // (or until we get a shutdown request).
    let protocol = Arc::new(Protocol::new(
        stream,
        rak.clone(),
        dispatcher.clone(),
        version,
    ));

    protocol.start();

    info!(logger, "Protocol handler terminated, shutting down");
}
