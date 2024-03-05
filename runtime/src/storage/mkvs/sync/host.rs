use std::{any::Any, sync::Arc};

use anyhow::Result;

use crate::{
    protocol::{Protocol, ProtocolError},
    storage::mkvs::sync::{
        GetPrefixesRequest, GetRequest, IterateRequest, ProofResponse, ReadSync,
    },
    types::{
        Body, HostStorageEndpoint, StorageSyncRequest, StorageSyncRequestWithEndpoint,
        StorageSyncResponse,
    },
};

/// A proxy read syncer which forwards calls to the runtime host.
pub struct HostReadSyncer {
    protocol: Arc<Protocol>,
    endpoint: HostStorageEndpoint,
}

impl HostReadSyncer {
    /// Construct a new host proxy instance.
    pub fn new(protocol: Arc<Protocol>, endpoint: HostStorageEndpoint) -> HostReadSyncer {
        HostReadSyncer { protocol, endpoint }
    }

    fn call_host_with_proof(&self, request: StorageSyncRequest) -> Result<ProofResponse> {
        let request = Body::HostStorageSyncRequest(StorageSyncRequestWithEndpoint {
            endpoint: self.endpoint,
            request,
        });
        match self.protocol.call_host(request) {
            Ok(Body::HostStorageSyncResponse(StorageSyncResponse::ProofResponse(response))) => {
                Ok(response)
            }
            Ok(_) => Err(ProtocolError::InvalidResponse.into()),
            Err(error) => Err(error.into()),
        }
    }
}

impl ReadSync for HostReadSyncer {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn sync_get(&mut self, request: GetRequest) -> Result<ProofResponse> {
        self.call_host_with_proof(StorageSyncRequest::SyncGet(request))
    }

    fn sync_get_prefixes(&mut self, request: GetPrefixesRequest) -> Result<ProofResponse> {
        self.call_host_with_proof(StorageSyncRequest::SyncGetPrefixes(request))
    }

    fn sync_iterate(&mut self, request: IterateRequest) -> Result<ProofResponse> {
        self.call_host_with_proof(StorageSyncRequest::SyncIterate(request))
    }
}
