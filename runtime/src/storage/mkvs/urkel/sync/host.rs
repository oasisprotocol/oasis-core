use std::{any::Any, sync::Arc};

use failure::Fallible;
use io_context::Context;

use crate::{
    protocol::{Protocol, ProtocolError},
    storage::mkvs::urkel::sync::*,
    types::{Body, StorageSyncRequest, StorageSyncResponse},
};

/// A proxy read syncer which forwards calls to the runtime host.
pub struct HostReadSyncer {
    protocol: Arc<Protocol>,
}

impl HostReadSyncer {
    /// Construct a new host proxy instance.
    pub fn new(protocol: Arc<Protocol>) -> HostReadSyncer {
        HostReadSyncer { protocol: protocol }
    }

    fn make_request_with_proof(
        &self,
        ctx: Context,
        request: StorageSyncRequest,
    ) -> Fallible<ProofResponse> {
        let request = Body::HostStorageSyncRequest { request };
        match self.protocol.make_request(ctx, request) {
            Ok(Body::HostStorageSyncResponse {
                response: StorageSyncResponse::ProofResponse(response),
            }) => Ok(response),
            Ok(_) => Err(ProtocolError::InvalidResponse.into()),
            Err(error) => Err(error),
        }
    }
}

impl ReadSync for HostReadSyncer {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn sync_get(&mut self, ctx: Context, request: GetRequest) -> Fallible<ProofResponse> {
        self.make_request_with_proof(ctx, StorageSyncRequest::SyncGet(request))
    }

    fn sync_get_prefixes(
        &mut self,
        ctx: Context,
        request: GetPrefixesRequest,
    ) -> Fallible<ProofResponse> {
        self.make_request_with_proof(ctx, StorageSyncRequest::SyncGetPrefixes(request))
    }

    fn sync_iterate(&mut self, ctx: Context, request: IterateRequest) -> Fallible<ProofResponse> {
        self.make_request_with_proof(ctx, StorageSyncRequest::SyncIterate(request))
    }
}
