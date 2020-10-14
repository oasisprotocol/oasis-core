//! A ReadSync implementation that can be used to test interoperability
//! with a storage server over the gRPC protocol.
//!
//! This should only be used for testing.
use std::{
    any::Any,
    process::{Child, Command},
    sync::Arc,
};

use anyhow::Result;
use grpcio::{ChannelBuilder, EnvBuilder};
use io_context::Context;
use tempfile::{self, TempDir};

use super::{rpc, Driver};
use crate::{
    common::{crypto::hash::Hash, namespace::Namespace},
    storage::mkvs::{sync::*, tree::RootType, WriteLog},
};

/// Location of the protocol server binary.
const PROTOCOL_SERVER_BINARY: &'static str = env!("OASIS_STORAGE_PROTOCOL_SERVER_BINARY");

/// Interoperability protocol server for testing storage.
pub struct ProtocolServer {
    server_process: Child,
    client: rpc::StorageClient,
    #[allow(unused)]
    datadir: TempDir,
}

struct ProtocolServerReadSyncer {
    client: rpc::StorageClient,
}

impl ProtocolServer {
    /// Create a new protocol server for testing.
    pub fn new() -> Self {
        let datadir = tempfile::Builder::new()
            .prefix("oasis-test-storage-protocol-server")
            .tempdir()
            .expect("failed to create temporary data directory");
        let socket_path = datadir.path().join("socket");

        // Start protocol server.
        let server_process = Command::new(PROTOCOL_SERVER_BINARY)
            .arg("proto-server")
            .arg("--datadir")
            .arg(datadir.path())
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
        let client = rpc::StorageClient::new(channel);

        Self {
            server_process,
            client,
            datadir,
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
        drop(self.server_process.wait());
    }
}

impl Driver for ProtocolServer {
    fn apply(&self, write_log: &WriteLog, root_hash: Hash, namespace: Namespace, version: u64) {
        self.apply_existing(write_log, Hash::empty_hash(), root_hash, namespace, version)
    }

    fn apply_existing(
        &self,
        write_log: &WriteLog,
        existing_root: Hash,
        root_hash: Hash,
        namespace: Namespace,
        version: u64,
    ) {
        self.client
            .apply(&rpc::ApplyRequest {
                namespace,
                root_type: RootType::State, // Doesn't matter for tests.
                src_round: version,
                src_root: existing_root,
                dst_round: version,
                dst_root: root_hash,
                writelog: write_log.clone(),
            })
            .expect("apply failed")
    }
}

impl ReadSync for ProtocolServerReadSyncer {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn sync_get(&mut self, _ctx: Context, request: GetRequest) -> Result<ProofResponse> {
        Ok(self.client.sync_get(&request)?)
    }

    fn sync_get_prefixes(
        &mut self,
        _ctx: Context,
        request: GetPrefixesRequest,
    ) -> Result<ProofResponse> {
        Ok(self.client.sync_get_prefixes(&request)?)
    }

    fn sync_iterate(&mut self, _ctx: Context, request: IterateRequest) -> Result<ProofResponse> {
        Ok(self.client.sync_iterate(&request)?)
    }
}
