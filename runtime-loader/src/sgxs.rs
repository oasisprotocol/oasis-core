//! SGX runtime loader.
use std::{
    io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult},
    os::unix::net::UnixStream,
};

use aesm_client::AesmClient;
use enclave_runner::{
    usercalls::{SyncStream, UsercallExtension},
    EnclaveBuilder,
};
use failure::{format_err, Fallible};
use sgxs_loaders::isgx::Device as IsgxDevice;

use crate::Loader;

/// SGX usercall extension for exposing the worker host to the enclave.
#[derive(Debug)]
struct HostService {
    host_socket: String,
}

impl HostService {
    fn new(host_socket: String) -> HostService {
        HostService { host_socket }
    }
}

impl UsercallExtension for HostService {
    fn connect_stream(
        &self,
        addr: &str,
        _local_addr: Option<&mut String>,
        _peer_addr: Option<&mut String>,
    ) -> IoResult<Option<Box<dyn SyncStream>>> {
        match &*addr {
            "worker-host" => {
                // Connect to worker host socket.
                let stream = UnixStream::connect(self.host_socket.clone())?;
                Ok(Some(Box::new(stream)))
            }
            _ => Err(IoError::new(IoErrorKind::Other, "invalid destination")),
        }
    }
}

/// SGX runtime loader.
pub struct SgxsLoader;

impl Loader for SgxsLoader {
    fn run(
        &self,
        filename: String,
        signature_filename: Option<&str>,
        host_socket: String,
    ) -> Fallible<()> {
        let sig = match signature_filename {
            Some(f) => f,
            None => {
                return Err(format_err!("signature file is required"));
            }
        };

        // Spawn the SGX enclave.
        let mut device = IsgxDevice::new()?
            .einittoken_provider(AesmClient::new())
            .build();

        let mut enclave_builder = EnclaveBuilder::new(filename.as_ref());
        enclave_builder.signature(sig)?;
        enclave_builder.usercall_extension(HostService::new(host_socket));
        let enclave = enclave_builder.build(&mut device)?;

        Ok(enclave.run()?)
    }
}
