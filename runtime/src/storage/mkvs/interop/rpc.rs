use std::{path::PathBuf, time::Duration};

use anyhow::Result;
use base64::STANDARD;
use jsonrpc::{simple_uds::UdsTransport, Client};
use serde::{Deserialize, Serialize};

use crate::{
    common::{crypto::hash::Hash, namespace::Namespace},
    storage::mkvs::{sync, tree::RootType, WriteLog},
};

// Calls should still have a timeout to handle the case where the interop server exits prematurely.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Default, cbor::Encode, cbor::Decode)]
pub struct ApplyRequest {
    pub namespace: Namespace,
    pub root_type: RootType,
    pub src_round: u64,
    pub src_root: Hash,
    pub dst_round: u64,
    pub dst_root: Hash,
    pub writelog: WriteLog,
}

base64_serde_type!(Base64Standard, STANDARD);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RPCRequest {
    #[serde(with = "Base64Standard")]
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RPCResponse {
    #[serde(with = "Base64Standard")]
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplyResponse {}

/// A (simplified) storage gRPC service client.
///
/// # Note
///
/// This client only implements methods required for testing the
/// interoperability of the read syncer interface.
pub struct StorageClient {
    client: Client,
    socket_path: PathBuf,
}

impl StorageClient {
    pub fn new(socket_path: PathBuf) -> Self {
        let transport = UdsTransport {
            sockpath: socket_path.clone(),
            timeout: Some(CALL_TIMEOUT),
        };
        StorageClient {
            client: Client::with_transport(transport),
            socket_path: socket_path,
        }
    }

    pub fn apply(&self, request: &ApplyRequest) -> Result<()> {
        let req = RPCRequest {
            payload: cbor::to_vec(request.clone()),
        };
        match self
            .client
            .call::<ApplyResponse>("Database.Apply", &[jsonrpc::arg(req)])
        {
            Ok(_) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    pub fn sync_get(&self, request: &sync::GetRequest) -> Result<sync::ProofResponse> {
        let req = RPCRequest {
            payload: cbor::to_vec(request.clone()),
        };
        match self
            .client
            .call::<RPCResponse>("Database.SyncGet", &[jsonrpc::arg(req)])
        {
            Ok(resp) => match cbor::from_slice::<sync::ProofResponse>(&resp.payload) {
                Ok(proof) => Ok(proof),
                Err(err) => Err(err.into()),
            },
            Err(err) => Err(err.into()),
        }
    }

    pub fn sync_get_prefixes(
        &self,
        request: &sync::GetPrefixesRequest,
    ) -> Result<sync::ProofResponse> {
        let req = RPCRequest {
            payload: cbor::to_vec(request.clone()),
        };
        match self
            .client
            .call::<RPCResponse>("Database.SyncGetPrefixes", &[jsonrpc::arg(req)])
        {
            Ok(resp) => match cbor::from_slice::<sync::ProofResponse>(&resp.payload) {
                Ok(proof) => Ok(proof),
                Err(err) => Err(err.into()),
            },
            Err(err) => Err(err.into()),
        }
    }

    pub fn sync_iterate(&self, request: &sync::IterateRequest) -> Result<sync::ProofResponse> {
        let req = RPCRequest {
            payload: cbor::to_vec(request.clone()),
        };
        match self
            .client
            .call::<RPCResponse>("Database.SyncIterate", &[jsonrpc::arg(req)])
        {
            Ok(resp) => match cbor::from_slice::<sync::ProofResponse>(&resp.payload) {
                Ok(proof) => Ok(proof),
                Err(err) => Err(err.into()),
            },
            Err(err) => Err(err.into()),
        }
    }
}

impl Clone for StorageClient {
    fn clone(&self) -> Self {
        StorageClient::new(self.socket_path.clone())
    }
}
