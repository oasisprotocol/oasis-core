//! A ReadSync implementation that can be used to test interoperability
//! with a storage server over the gRPC protocol.
//!
//! This should only be used for testing.
use std::{
    any::Any,
    process::{Child, Command},
    sync::Arc,
};

use failure::Fallible;
use grpcio::{CallOption, ChannelBuilder, EnvBuilder};
use io_context::Context;
use tempfile::NamedTempFile;

use super::{
    grpc::{self, storage::StorageClient},
    Driver,
};
use crate::{
    common::{cbor, crypto::hash::Hash, roothash::Namespace},
    storage::mkvs::{urkel::sync::*, WriteLog},
};

/// Location of the protocol server binary.
const PROTOCOL_SERVER_BINARY: &'static str = env!("EKIDEN_PROTOCOL_SERVER_BINARY");

/// Interoperability protocol server for testing storage.
pub struct ProtocolServer {
    server_process: Child,
    client: StorageClient,
}

struct ProtocolServerReadSyncer {
    client: StorageClient,
}

impl ProtocolServer {
    /// Create a new protocol server for testing.
    pub fn new() -> Self {
        let socket_path = NamedTempFile::new()
            .expect("failed to create temporary socket path")
            .into_temp_path()
            .to_path_buf();

        // Start protocol server.
        let server_process = Command::new(PROTOCOL_SERVER_BINARY)
            .arg("proto-server")
            .arg("--socket")
            .arg(socket_path.clone())
            .spawn()
            .expect("protocol server failed to start");

        // Create connection with the protocol server.
        let env = Arc::new(EnvBuilder::new().build());
        let channel = ChannelBuilder::new(env)
            .max_receive_message_len(i32::max_value())
            .max_send_message_len(i32::max_value())
            .connect(&format!("unix:{}", socket_path.to_str().unwrap()));
        let client = StorageClient::new(channel);

        Self {
            server_process,
            client,
        }
    }

    /// Return a ReadSync backed by the protocol server
    pub fn read_sync(&self) -> Box<dyn ReadSync> {
        Box::new(ProtocolServerReadSyncer {
            client: self.client.clone(),
        })
    }
}

impl Drop for ProtocolServer {
    fn drop(&mut self) {
        // Stop protocol server.
        drop(self.server_process.kill());
    }
}

impl Driver for ProtocolServer {
    fn apply(&self, write_log: &WriteLog, root_hash: Hash, namespace: Namespace, round: u64) {
        let mut rq = grpc::storage::ApplyRequest::new();
        rq.set_namespace(namespace.as_ref().to_vec());
        rq.set_src_round(round);
        rq.set_src_root(Hash::empty_hash().as_ref().to_vec());
        rq.set_dst_round(round);
        rq.set_dst_root(root_hash.as_ref().to_vec());
        rq.set_log(
            write_log
                .iter()
                .map(|entry| {
                    let mut e = grpc::storage::LogEntry::new();
                    e.set_key(entry.key.clone());
                    e.set_value(entry.value.clone());
                    e
                })
                .collect::<Vec<_>>()
                .into(),
        );

        self.client
            .apply_opt(&rq, CallOption::default().wait_for_ready(true))
            .expect("apply failed");
    }
}

impl ReadSync for ProtocolServerReadSyncer {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn sync_get(&mut self, _ctx: Context, request: GetRequest) -> Fallible<ProofResponse> {
        let mut rq = grpc::storage::ReadSyncerRequest::new();
        rq.set_request(cbor::to_vec(&request));

        let response = self
            .client
            .sync_get_opt(&rq, CallOption::default().wait_for_ready(true))?;
        Ok(cbor::from_slice(response.get_response())?)
    }

    fn sync_get_prefixes(
        &mut self,
        _ctx: Context,
        request: GetPrefixesRequest,
    ) -> Fallible<ProofResponse> {
        let mut rq = grpc::storage::ReadSyncerRequest::new();
        rq.set_request(cbor::to_vec(&request));

        let response = self
            .client
            .sync_get_prefixes_opt(&rq, CallOption::default().wait_for_ready(true))?;
        Ok(cbor::from_slice(response.get_response())?)
    }

    fn sync_iterate(&mut self, _ctx: Context, request: IterateRequest) -> Fallible<ProofResponse> {
        let mut rq = grpc::storage::ReadSyncerRequest::new();
        rq.set_request(cbor::to_vec(&request));

        let response = self
            .client
            .sync_iterate_opt(&rq, CallOption::default().wait_for_ready(true))?;
        Ok(cbor::from_slice(response.get_response())?)
    }
}
