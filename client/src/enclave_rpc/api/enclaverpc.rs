//! Client for service defined in go/runtime/enclaverpc/api.
use grpcio::{CallOption, Channel, Client, ClientUnaryReceiver, Result};
use serde_bytes::ByteBuf;
use serde_derive::{Deserialize, Serialize};

use oasis_core_runtime::common::runtime::RuntimeId;

/// A call_enclave request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallEnclaveRequest {
    /// Runtime ID of the target runtime.
    pub runtime_id: RuntimeId,
    /// Endpoint name.
    pub endpoint: String,
    /// EnclaveRPC payload to transport to the target runtime.
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

grpc_method!(
    METHOD_CALL_ENCLAVE,
    "/oasis-core.EnclaveRPC/CallEnclave",
    CallEnclaveRequest,
    ByteBuf
);

/// An EnclaveRPC gRPC service client.
#[derive(Clone)]
pub struct EnclaveRPCClient {
    client: Client,
}

impl EnclaveRPCClient {
    /// Create a new EnclaveRPC client.
    pub fn new(channel: Channel) -> Self {
        EnclaveRPCClient {
            client: Client::new(channel),
        }
    }

    /// Send the request bytes to the target enclave.
    pub fn call_enclave(
        &self,
        request: &CallEnclaveRequest,
        opt: CallOption,
    ) -> Result<ClientUnaryReceiver<ByteBuf>> {
        self.client
            .unary_call_async(&METHOD_CALL_ENCLAVE, &request, opt)
    }
}
