//! Runtime initialization.
use std::sync::Arc;

use anyhow::Result;
use slog::{error, info};

use crate::{
    common::logger::{get_logger, init_logger},
    config::Config,
    dispatcher::{Dispatcher, Initializer},
    future::new_tokio_runtime,
    identity::Identity,
    protocol::{Protocol, Stream},
    TeeType, BUILD_INFO,
};

/// Starts the runtime.
pub fn start_runtime(initializer: Box<dyn Initializer>, config: Config) {
    // Initialize logging.
    init_logger(log::Level::Info);
    let logger = get_logger("runtime");
    info!(logger, "Runtime is starting");

    // Perform TDX-specific early initialization.
    #[cfg(feature = "tdx")]
    if BUILD_INFO.tee_type == TeeType::Tdx {
        crate::common::tdx::init::init();
    }

    // Initialize runtime identity with runtime attestation key and runtime encryption key.
    let identity = Arc::new(Identity::new());

    // Initialize the async Tokio runtime.
    let tokio_runtime = new_tokio_runtime();
    let tokio_handle = tokio_runtime.handle();

    // Initialize the dispatcher.
    let dispatcher = Dispatcher::new(tokio_handle.clone(), initializer, identity.clone());

    // Connect to the runtime host.
    info!(logger, "Establishing connection with the worker host");

    let stream = match connect() {
        Ok(stream) => stream,
        Err(err) => {
            error!(logger, "Failed to connect with the worker host"; "err" => %err);
            return;
        }
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

/// Establish a connection with the host.
fn connect() -> Result<Stream> {
    match BUILD_INFO.tee_type {
        #[cfg(not(target_env = "sgx"))]
        TeeType::Sgx | TeeType::None => {
            let stream = std::os::unix::net::UnixStream::connect(
                std::env::var("OASIS_WORKER_HOST").unwrap_or_default(),
            )?;
            Ok(Stream::Unix(stream))
        }

        #[cfg(target_env = "sgx")]
        TeeType::Sgx => {
            let stream = std::net::TcpStream::connect("worker-host")?;
            Ok(Stream::Tcp(stream))
        }

        #[cfg(feature = "tdx")]
        TeeType::Tdx => {
            /// VSOCK port used for the Runtime Host Protocol.
            const VSOCK_PORT_RHP: u32 = 1;

            // Accept first connection.
            let listener = vsock::VsockListener::bind(&vsock::VsockAddr::new(
                libc::VMADDR_CID_ANY,
                VSOCK_PORT_RHP,
            ))?;
            let stream = listener
                .incoming()
                .next()
                .ok_or(anyhow::anyhow!("failed to accept connection"))??;
            Ok(Stream::Vsock(stream))
        }

        #[allow(unreachable_patterns)]
        _ => Err(anyhow::anyhow!("unsupported TEE type")),
    }
}
