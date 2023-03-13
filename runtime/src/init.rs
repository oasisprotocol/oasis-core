//! Runtime initialization.
use std::sync::Arc;

use log;
use slog::{error, info};

use crate::{
    common::logger::{get_logger, init_logger},
    config::Config,
    dispatcher::{Dispatcher, Initializer},
    future::new_tokio_runtime,
    identity::Identity,
    protocol::{Protocol, Stream},
};

/// Starts the runtime.
pub fn start_runtime(initializer: Box<dyn Initializer>, config: Config) {
    // Output backtraces in debug builds.
    #[cfg(debug_assertions)]
    std::env::set_var("RUST_BACKTRACE", "1");

    // Initialize logging.
    init_logger(log::Level::Info);
    let logger = get_logger("runtime");
    info!(logger, "Runtime is starting");

    // Initialize runtime identity with runtime attestation key and runtime encryption key.
    let identity = Arc::new(Identity::new());

    // Initialize the async Tokio runtime.
    let tokio_runtime = new_tokio_runtime();
    let tokio_handle = tokio_runtime.handle();

    // Initialize the dispatcher.
    let dispatcher = Dispatcher::new(tokio_handle.clone(), initializer, identity.clone());

    info!(logger, "Establishing connection with the worker host");

    #[cfg(not(target_env = "sgx"))]
    let stream = match Stream::connect(std::env::var("OASIS_WORKER_HOST").unwrap_or_default()) {
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

    // Initialize the protocol handler loop.
    let protocol = Arc::new(Protocol::new(
        tokio_handle.clone(),
        stream,
        identity,
        dispatcher,
        config,
    ));

    // Start handling protocol messages. This blocks the main thread forever
    // (or until we get a shutdown request).
    protocol.start();

    info!(logger, "Protocol handler terminated, shutting down");
}
