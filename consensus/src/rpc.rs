use std;
use std::sync::{mpsc, Arc, Mutex};

use futures::Future;

use grpcio;
use grpcio::{RpcStatus, RpcStatusCode};

use protobuf::{self, Message};

use ekiden_consensus_api::{self, Consensus};

use super::state;

use super::tendermint::BroadcastRequest;

struct ConsensusServiceInner {
    state: Arc<Mutex<state::State>>,
    // TODO: Clone the sender for each thread and store it in thread-local storage.
    broadcast_channel: Mutex<mpsc::Sender<BroadcastRequest>>,
}

#[derive(Clone)]
pub struct ConsensusService {
    inner: Arc<ConsensusServiceInner>,
}

impl ConsensusService {
    pub fn new(
        state: Arc<Mutex<state::State>>,
        broadcast_channel: mpsc::Sender<BroadcastRequest>,
    ) -> Self {
        ConsensusService {
            inner: Arc::new(ConsensusServiceInner {
                state: state,
                broadcast_channel: Mutex::new(broadcast_channel),
            }),
        }
    }

    fn replace_fallible(
        &self,
        payload: Vec<u8>,
    ) -> Result<ekiden_consensus_api::ReplaceResponse, Box<std::error::Error>> {
        let mut stored = ekiden_consensus_api::StoredTx::new();
        stored.set_replace(payload);
        let stored_bytes = stored.write_to_bytes()?;

        // check attestation - early reject
        state::State::check_tx(&stored_bytes)?;

        // Create a one-shot channel for response.
        let (tx, rx) = mpsc::channel();
        let req = BroadcastRequest {
            response: tx,
            payload: stored_bytes,
        };

        let broadcast_channel = self.inner.broadcast_channel.lock().unwrap();
        broadcast_channel.send(req).unwrap();
        rx.recv().unwrap()?;

        Ok(ekiden_consensus_api::ReplaceResponse::new())
    }

    fn add_diff_fallible(
        &self,
        payload: Vec<u8>,
    ) -> Result<ekiden_consensus_api::AddDiffResponse, Box<std::error::Error>> {
        let mut stored = ekiden_consensus_api::StoredTx::new();
        stored.set_diff(payload);
        let stored_bytes = stored.write_to_bytes()?;

        // check attestation - early reject
        state::State::check_tx(&stored_bytes)?;

        // Create a one-shot channel for response.
        let (tx, rx) = mpsc::channel();
        let req = BroadcastRequest {
            response: tx,
            payload: stored_bytes,
        };

        let broadcast_channel = self.inner.broadcast_channel.lock().unwrap();
        broadcast_channel.send(req).unwrap();
        rx.recv().unwrap()?;

        Ok(ekiden_consensus_api::AddDiffResponse::new())
    }
}

impl Consensus for ConsensusService {
    fn get(
        &self,
        ctx: grpcio::RpcContext,
        _req: ekiden_consensus_api::GetRequest,
        sink: grpcio::UnarySink<ekiden_consensus_api::GetResponse>,
    ) {
        let s = self.inner.state.lock().unwrap();
        let f = match s.everything {
            Some(ref si) => {
                let mut response = ekiden_consensus_api::GetResponse::new();
                {
                    let mut checkpoint = response.mut_checkpoint();
                    checkpoint.set_payload(si.checkpoint.clone());
                    checkpoint.set_height(si.checkpoint_height);
                }
                response.set_diffs(protobuf::RepeatedField::from_vec(si.diffs.clone()));
                sink.success(response)
            }
            None => sink.fail(RpcStatus::new(
                RpcStatusCode::Internal,
                Some("State not initialized.".to_owned()),
            )),
        };
        ctx.spawn(f.map_err(|_error| ()));
    }

    fn get_diffs(
        &self,
        ctx: grpcio::RpcContext,
        req: ekiden_consensus_api::GetDiffsRequest,
        sink: grpcio::UnarySink<ekiden_consensus_api::GetDiffsResponse>,
    ) {
        let s = self.inner.state.lock().unwrap();
        let f = match s.everything {
            Some(ref si) => {
                let mut response = ekiden_consensus_api::GetDiffsResponse::new();
                if si.checkpoint_height > req.get_since_height() {
                    // We don't have diffs going back far enough.
                    {
                        let mut checkpoint = response.mut_checkpoint();
                        checkpoint.set_payload(si.checkpoint.clone());
                        checkpoint.set_height(si.checkpoint_height);
                    }
                    response.set_diffs(protobuf::RepeatedField::from_vec(si.diffs.clone()));
                } else {
                    let num_known = req.get_since_height() - si.checkpoint_height;
                    response.set_diffs(protobuf::RepeatedField::from_vec(
                        si.diffs[num_known as usize..].to_vec(),
                    ));
                }
                sink.success(response)
            }
            None => sink.fail(RpcStatus::new(
                RpcStatusCode::Internal,
                Some("State not initialized.".to_owned()),
            )),
        };
        ctx.spawn(f.map_err(|_error| ()));
    }

    fn replace(
        &self,
        ctx: grpcio::RpcContext,
        req: ekiden_consensus_api::ReplaceRequest,
        sink: grpcio::UnarySink<ekiden_consensus_api::ReplaceResponse>,
    ) {
        let f = match self.replace_fallible(req.get_payload().to_vec()) {
            Ok(res) => sink.success(res),
            Err(e) => sink.fail(RpcStatus::new(
                RpcStatusCode::Internal,
                Some(e.description().to_owned()),
            )),
        };
        ctx.spawn(f.map_err(|_error| ()));
    }

    fn add_diff(
        &self,
        ctx: grpcio::RpcContext,
        req: ekiden_consensus_api::AddDiffRequest,
        sink: grpcio::UnarySink<ekiden_consensus_api::AddDiffResponse>,
    ) {
        let f = match self.add_diff_fallible(req.get_payload().to_vec()) {
            Ok(res) => sink.success(res),
            Err(e) => sink.fail(RpcStatus::new(
                RpcStatusCode::Internal,
                Some(e.description().to_owned()),
            )),
        };
        ctx.spawn(f.map_err(|_error| ()));
    }
}
