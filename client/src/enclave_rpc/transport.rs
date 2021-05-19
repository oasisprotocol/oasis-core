use std::sync::Arc;

use anyhow::{anyhow, Error as AnyError};
use futures::future::{self, BoxFuture};
#[cfg(not(target_env = "sgx"))]
use futures::TryFutureExt;
use io_context::Context;

#[cfg(not(target_env = "sgx"))]
use oasis_core_runtime::common::namespace::Namespace;
use oasis_core_runtime::{common::cbor, enclave_rpc::types, protocol::Protocol, types::Body};

#[cfg(not(target_env = "sgx"))]
use super::api::{CallEnclaveRequest, EnclaveRPCClient};

/// An EnclaveRPC transport.
pub trait Transport: Send + Sync {
    fn write_message(
        &self,
        ctx: Context,
        session_id: types::SessionID,
        data: Vec<u8>,
        untrusted_plaintext: String,
    ) -> BoxFuture<Result<Vec<u8>, AnyError>> {
        // Frame message.
        let frame = types::Frame {
            session: session_id,
            untrusted_plaintext: untrusted_plaintext,
            payload: data,
        };

        self.write_message_impl(ctx, cbor::to_vec(&frame))
    }

    fn write_message_impl(
        &self,
        ctx: Context,
        data: Vec<u8>,
    ) -> BoxFuture<Result<Vec<u8>, AnyError>>;
}

/// A transport implementation which can be used from inside the runtime and uses the Runtime Host
/// Protocol to transport EnclaveRPC frames.
pub struct RuntimeTransport {
    pub protocol: Arc<Protocol>,
    pub endpoint: String,
}

impl Transport for RuntimeTransport {
    fn write_message_impl(
        &self,
        ctx: Context,
        data: Vec<u8>,
    ) -> BoxFuture<Result<Vec<u8>, AnyError>> {
        // NOTE: This is not actually async in SGX, but futures should be
        //       dispatched on the current thread anyway.
        let rsp = self.protocol.make_request(
            ctx,
            Body::HostRPCCallRequest {
                endpoint: self.endpoint.clone(),
                request: data,
            },
        );

        match rsp {
            Err(err) => Box::pin(future::err(err)),
            Ok(Body::HostRPCCallResponse { response }) => Box::pin(future::ok(response)),
            Ok(_) => Box::pin(future::err(anyhow!("bad response type"))),
        }
    }
}

/// A transport implementation which uses gRPC to transport EnclaveRPC frames.
#[cfg(not(target_env = "sgx"))]
pub struct GrpcTransport {
    pub grpc_client: EnclaveRPCClient,
    pub runtime_id: Namespace,
    pub endpoint: String,
}

#[cfg(not(target_env = "sgx"))]
impl Transport for GrpcTransport {
    fn write_message_impl(
        &self,
        _ctx: Context,
        data: Vec<u8>,
    ) -> BoxFuture<Result<Vec<u8>, AnyError>> {
        let req = CallEnclaveRequest {
            runtime_id: self.runtime_id,
            endpoint: self.endpoint.clone(),
            payload: data,
        };

        match self.grpc_client.call_enclave(&req, Default::default()) {
            Ok(rsp) => Box::pin(rsp.map_ok(|r| r.into_vec()).map_err(|error| error.into())),
            Err(error) => Box::pin(future::err(error.into())),
        }
    }
}
