//! SGX runtime loader.
use std::{
    future::Future,
    io::{Error as IoError, Result as IoResult},
    pin::Pin,
};

use aesm_client::AesmClient;
use anyhow::{anyhow, Result};
use enclave_runner::{
    usercalls::{AsyncStream, UsercallExtension},
    EnclaveBuilder,
};
use futures::future::FutureExt;
use sgxs_loaders::isgx::Device as IsgxDevice;
use tokio::net::UnixStream;

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
impl UsercallExtension for HostService {
    fn connect_stream<'future>(
        &'future self,
        addr: &'future str,
        _local_addr: Option<&'future mut String>,
        _peer_addr: Option<&'future mut String>,
    ) -> Pin<Box<dyn Future<Output = IoResult<Option<Box<dyn AsyncStream>>>> + 'future>> {
        async move {
            match addr {
                "worker-host" | "worker-host:0" => {
                    // Connect to worker host socket.
                    let stream = UnixStream::connect(self.host_socket.clone()).await?;
                    let async_stream: Box<dyn AsyncStream> = Box::new(stream);
                    Ok(Some(async_stream))
                }
                _ if self.allow_network => {
                    // Unknown destination and network access is allowed, pass to default handler.
                    Ok(None)
                }
                _ => {
                    // Unknown destination and network access is not allowed, reject.
                    Err(IoError::other("invalid destination"))
                }
            }
        }
        .boxed_local()
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

        // Spawn the SGX enclave.
        let mut device = IsgxDevice::new()?
            .einittoken_provider(AesmClient::new())
            .build();

        let mut enclave_builder = EnclaveBuilder::new(filename.as_ref());
        enclave_builder.signature(sig)?;
        enclave_builder.usercall_extension(HostService::new(host_socket, allow_network));
        let enclave = enclave_builder
            .build(&mut device)
            .map_err(|err| anyhow!("{}", err))?;

        enclave.run().map_err(|err| anyhow!("{}", err))
    }
}
