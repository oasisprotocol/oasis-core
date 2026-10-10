//! SGX runtime loader.
use std::{
    future::Future,
    io::{Error as IoError, Result as IoResult},
    pin::Pin,
};

use aesm_client::AesmClient;
use anyhow::{anyhow, Result};
use enclave_runner::{
    stream_router::{AsyncStream, OsStreamRouter, StreamRouter},
    EnclaveBuilder,
};
use enclave_runner_sgx::EnclaveBuilder as EnclaveBuilderSgx;
use sgxs_loaders::isgx::Device as IsgxDevice;
use tokio::net::{TcpStream, UnixStream};

use crate::Loader;

/// SGX usercall extension for exposing the worker host to the enclave.
#[derive(Debug)]
struct HostService {
    host_socket: String,
    allow_network: bool,
}

impl HostService {
    fn new(host_socket: &str, allow_network: bool) -> HostService {
        HostService {
            host_socket: host_socket.to_owned(),
            allow_network,
        }
    }
}

#[allow(clippy::type_complexity)]
impl StreamRouter for HostService {
    fn basic_streams(&self) -> Vec<Box<dyn AsyncStream>> {
        OsStreamRouter::new().basic_streams()
    }

    fn connect_stream<'future>(
        &'future self,
        addr: &'future str,
        _local_addr: Option<&'future mut String>,
        _peer_addr: Option<&'future mut String>,
    ) -> Pin<Box<dyn Future<Output = IoResult<Box<dyn AsyncStream>>> + Send + 'future>> {
        Box::pin(async move {
            match addr {
                "worker-host" | "worker-host:0" => {
                    // Connect to worker host socket.
                    let stream = UnixStream::connect(&self.host_socket).await?;
                    let async_stream: Box<dyn AsyncStream> = Box::new(stream);
                    Ok(async_stream)
                }
                _ if self.allow_network => {
                    // Unknown destination and network access is allowed.
                    // Connect directly using the default TCP transport.
                    let stream = TcpStream::connect(addr).await?;
                    let async_stream: Box<dyn AsyncStream> = Box::new(stream);
                    Ok(async_stream)
                }
                _ => {
                    // Unknown destination and network access is not allowed, reject.
                    Err(IoError::other("invalid destination"))
                }
            }
        })
    }

    fn bind_stream<'future>(
        &'future self,
        addr: &'future str,
        _local_addr: Option<&'future mut String>,
    ) -> std::pin::Pin<
        Box<
            dyn Future<Output = IoResult<Box<dyn enclave_runner::stream_router::AsyncListener>>>
                + Send
                + 'future,
        >,
    > {
        Box::pin(async move {
            Err(IoError::other(format!(
                "binding streams is not supported: {addr}"
            )))
        })
    }
}

/// SGX runtime loader.
pub struct SgxsLoader;

impl Loader for SgxsLoader {
    fn run(
        &self,
        filename: &str,
        signature_filename: Option<&str>,
        host_socket: &str,
        allow_network: bool,
    ) -> Result<()> {
        let sig = signature_filename.ok_or_else(|| anyhow!("signature file is required"))?;
        let mut sgx_builder = EnclaveBuilderSgx::new(filename.as_ref());
        sgx_builder.signature(sig)?;

        let stream_router: Box<dyn StreamRouter + Send + Sync> =
            Box::new(HostService::new(host_socket, allow_network));
        let mut enclave_builder = EnclaveBuilder::<_, enclave_runner::Command>::new(sgx_builder);
        enclave_builder.stream_router(stream_router);

        let device = IsgxDevice::new()?
            .einittoken_provider(AesmClient::new())
            .build();
        let enclave = enclave_builder.build(device)?;
        enclave.run()
    }
}
