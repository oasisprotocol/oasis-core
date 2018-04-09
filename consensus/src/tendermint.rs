use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use grpcio;

use super::generated::tendermint::{RequestBroadcastTx, ResponseBroadcastTx};
use super::generated::tendermint_grpc::BroadcastApiClient;

/// Broadcast request that can be sent via the proxy.
#[derive(Debug)]
pub struct BroadcastRequest {
    /// Raw broadcast payload.
    pub payload: Vec<u8>,
    /// Channel for sending the response.
    pub response: Sender<Result<ResponseBroadcastTx, grpcio::Error>>,
}

/// Proxy that runs the tendermint client in a separate thread.
pub struct TendermintProxy {}

impl TendermintProxy {
    /// Create a new Tendermint proxy instance.
    pub fn new(host: &str, port: u16, queue: Receiver<BroadcastRequest>) -> Self {
        let proxy = TendermintProxy {};
        proxy.start(host, port, queue);
        proxy
    }

    /// Start the proxy worker thread.
    fn start(&self, host: &str, port: u16, queue: Receiver<BroadcastRequest>) {
        let environment = Arc::new(grpcio::EnvBuilder::new().build());
        let channel =
            grpcio::ChannelBuilder::new(environment).connect(&format!("{}:{}", host, port));
        let client = BroadcastApiClient::new(channel);

        thread::spawn(move || {
            // Process requests in queue.
            for request in queue {
                let mut broadcast_request = RequestBroadcastTx::new();
                broadcast_request.set_tx(request.payload);

                let response = match client.broadcast_tx(&broadcast_request) {
                    Ok(response) => Ok(response),
                    Err(error) => Err(error),
                };

                request.response.send(response).unwrap();
            }
        });
    }
}
