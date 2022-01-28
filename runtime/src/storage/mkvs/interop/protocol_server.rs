//! A ReadSync implementation that can be used to test interoperability
//! with a storage server over the gRPC protocol.
//!
//! This should only be used for testing.
use std::{
    any::Any,
    fmt,
    process::{Child, Command},
    thread, time,
};

use anyhow::Result;
use io_context::Context;
use tempfile::{self, TempDir};

use super::{rpc, Driver};
use crate::{
    common::{crypto::hash::Hash, namespace::Namespace},
    storage::mkvs::{sync::*, tree::RootType, WriteLog},
};

/// Location of the protocol server binary.
static PROTOCOL_SERVER_BINARY: Option<&'static str> =
    option_env!("OASIS_STORAGE_PROTOCOL_SERVER_BINARY");

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

/// Interoperability protocol server fixtures.
pub enum Fixture {
    None,
    ConsensusMock,
}

impl fmt::Display for Fixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fixture::ConsensusMock => write!(f, "consensus_mock"),
            _ => write!(f, ""),
        }
    }
}

impl ProtocolServer {
    /// Create a new protocol server for testing.
    pub fn new(fixture: Option<Fixture>) -> Self {
        let datadir = tempfile::Builder::default()
            .prefix("oasis-test-storage-protocol-server")
            .tempdir()
            .expect("failed to create temporary data directory");
        let socket_path = datadir.path().join("socket");

        // Start protocol server.
        let server_binary = PROTOCOL_SERVER_BINARY.expect("no server binary configured");
        let mut server_cmd = Command::new(server_binary);
        server_cmd
            .arg("proto-server")
            .arg("--datadir")
            .arg(datadir.path())
            .arg("--socket")
            .arg(socket_path.clone())
            .arg("--fixture")
            .arg(fixture.unwrap_or(Fixture::None).to_string());
        let server_process = server_cmd.spawn().expect("protocol server failed to start");

        // Wait for the server to initialize, because the client is too
        // stupid to attempt to reconnect if it can't the first time around.
        thread::sleep(time::Duration::from_secs(5));

        // Create connection with the protocol server.
        let client = rpc::StorageClient::new(socket_path.clone());

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
