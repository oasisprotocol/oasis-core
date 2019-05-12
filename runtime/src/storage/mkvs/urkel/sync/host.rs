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
    ctx: Arc<Context>,
    protocol: Arc<Protocol>,
}

impl HostReadSyncer {
    /// Construct a new host proxy instance.
    pub fn new(context: Context, protocol: Arc<Protocol>) -> HostReadSyncer {
        HostReadSyncer {
            ctx: context.freeze(),
            protocol: protocol,
        }
    }
}

impl ReadSync for HostReadSyncer {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn get_subtree(&mut self, root_hash: Hash, id: NodeID, max_depth: u8) -> Fallible<Subtree> {
        let ctx = Context::create_child(&self.ctx);
        let req = Body::HostStorageSyncGetSubtreeRequest {
            root_hash: root_hash,
            node_path: id.path,
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

    fn get_path(&mut self, root_hash: Hash, key: Hash, start_depth: u8) -> Fallible<Subtree> {
        let ctx = Context::create_child(&self.ctx);
        let req = Body::HostStorageSyncGetPathRequest {
            root_hash: root_hash,
            key: key,
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

    fn get_node(&mut self, root_hash: Hash, id: NodeID) -> Fallible<NodeRef> {
        let ctx = Context::create_child(&self.ctx);
        let req = Body::HostStorageSyncGetNodeRequest {
            root_hash: root_hash,
            node_path: id.path,
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

    fn get_value(&mut self, root_hash: Hash, id: Hash) -> Fallible<Option<Value>> {
        let ctx = Context::create_child(&self.ctx);
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
