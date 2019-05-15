use std::{any::Any, cell::RefCell, rc::Rc, sync::Arc};

use failure::Fallible;
use io_context::Context;

use crate::{
    common::crypto::hash::Hash,
    protocol::{Protocol, ProtocolError},
    storage::mkvs::urkel::{marshal::*, sync::*, tree::*},
    types::Body,
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
}

impl ReadSync for HostReadSyncer {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn get_subtree(
        &mut self,
        ctx: Context,
        root_hash: Hash,
        id: NodeID,
        max_depth: u8,
    ) -> Fallible<Subtree> {
        let req = Body::HostStorageSyncGetSubtreeRequest {
            root_hash: root_hash,
            node_path: id.path.clone(),
            node_depth: id.depth,
            max_depth: max_depth,
        };
        match self.protocol.make_request(ctx, req) {
            Ok(Body::HostStorageSyncSerializedResponse { serialized }) => {
                let mut st = Subtree::new();
                st.unmarshal_binary(serialized.as_slice())?;
                Ok(st)
            }
            Ok(_) => Err(ProtocolError::InvalidResponse.into()),
            Err(error) => Err(error),
        }
    }

    fn get_path(
        &mut self,
        ctx: Context,
        root_hash: Hash,
        key: &Key,
        start_depth: u8,
    ) -> Fallible<Subtree> {
        let req = Body::HostStorageSyncGetPathRequest {
            root_hash: root_hash,
            key: key.clone(),
            start_depth: start_depth,
        };
        match self.protocol.make_request(ctx, req) {
            Ok(Body::HostStorageSyncSerializedResponse { serialized }) => {
                let mut st = Subtree::new();
                st.unmarshal_binary(serialized.as_slice())?;
                Ok(st)
            }
            Ok(_) => Err(ProtocolError::InvalidResponse.into()),
            Err(error) => Err(error),
        }
    }

    fn get_node(&mut self, ctx: Context, root_hash: Hash, id: NodeID) -> Fallible<NodeRef> {
        let req = Body::HostStorageSyncGetNodeRequest {
            root_hash: root_hash,
            node_path: id.path.clone(),
            node_depth: id.depth,
        };
        match self.protocol.make_request(ctx, req) {
            Ok(Body::HostStorageSyncSerializedResponse { serialized }) => {
                let mut node = NodeBox::default();
                node.unmarshal_binary(serialized.as_slice())?;
                Ok(Rc::new(RefCell::new(node)))
            }
            Ok(_) => Err(ProtocolError::InvalidResponse.into()),
            Err(error) => Err(error),
        }
    }

    fn get_value(&mut self, ctx: Context, root_hash: Hash, id: Hash) -> Fallible<Option<Value>> {
        let req = Body::HostStorageSyncGetValueRequest {
            root_hash: root_hash,
            value_id: id,
        };
        match self.protocol.make_request(ctx, req) {
            Ok(Body::HostStorageSyncSerializedResponse { serialized }) => Ok(Some(serialized)),
            Ok(_) => Err(ProtocolError::InvalidResponse.into()),
            Err(error) => Err(error),
        }
    }
}
