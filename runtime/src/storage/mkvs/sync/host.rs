use std::{any::Any, sync::Arc};

use anyhow::Result;
use io_context::Context;

use crate::{
    protocol::{Protocol, ProtocolError},
    storage::mkvs::sync::*,
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
        HostReadSyncer {
            protocol: protocol,
            endpoint: endpoint,
        }
    }

    fn make_request_with_proof(
        &self,
        ctx: Context,
        request: StorageSyncRequest,
    ) -> Result<ProofResponse> {
        let request = Body::HostStorageSyncRequest(StorageSyncRequestWithEndpoint {
            endpoint: self.endpoint,
            request,
        });
        match self.protocol.make_request(ctx, request) {
            Ok(Body::HostStorageSyncResponse(StorageSyncResponse::ProofResponse(response))) => {
                Ok(response)
            }
            Ok(_) => Err(ProtocolError::InvalidResponse.into()),
            Err(error) => Err(error),
        }
    }
}

impl ReadSync for HostReadSyncer {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn sync_get(&mut self, ctx: Context, request: GetRequest) -> Result<ProofResponse> {
        self.make_request_with_proof(ctx, StorageSyncRequest::SyncGet(request))
    }

    fn sync_get_prefixes(
        &mut self,
        ctx: Context,
        request: GetPrefixesRequest,
    ) -> Result<ProofResponse> {
        self.make_request_with_proof(ctx, StorageSyncRequest::SyncGetPrefixes(request))
    }

    fn sync_iterate(&mut self, ctx: Context, request: IterateRequest) -> Result<ProofResponse> {
        self.make_request_with_proof(ctx, StorageSyncRequest::SyncIterate(request))
    }
}
