//! Client for Tendermint JSON-RPC over WebSockets.
//!
//! Clients implement Ekiden interfaces by calling into a Tendermint node which
//! communicates with our ABCI applications.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64;
use jsonrpc_core::types::{Id, MethodCall, Output, Params, Version};
use serde_json;
use tokio_tungstenite;
use tungstenite;
use tungstenite::handshake::client::Request;
use tungstenite::protocol::Message;

use ekiden_common::environment::Environment;
use ekiden_common::error::Error;
use ekiden_common::futures::prelude::*;
use ekiden_common::futures::sync::{mpsc, oneshot};

enum Subscriber {
    OneShot(oneshot::Sender<Output>),
    Stream(mpsc::UnboundedSender<Output>),
}

struct Inner {
    /// Environment where the client is running.
    environment: Arc<Environment>,
    /// Message sender.
    request_tx: mpsc::UnboundedSender<Message>,
    /// Subscriptions.
    subscriptions: Mutex<HashMap<usize, Subscriber>>,
    /// Last call identifier.
    last_call_id: AtomicUsize,
}

/// Tendermint JSON-RPC over WebSockets client.
pub struct TendermintClient {
    inner: Arc<Inner>,
}

impl TendermintClient {
    /// Create new Tendermint client.
    pub fn new(environment: Arc<Environment>, address: &SocketAddr) -> Self {
        let (request_tx, request_rx) = mpsc::unbounded();
        let instance = Self {
            inner: Arc::new(Inner {
                environment,
                request_tx,
                subscriptions: Mutex::new(HashMap::new()),
                last_call_id: AtomicUsize::new(0),
            }),
        };
        instance.connect(address, request_rx);

        instance
    }

    /// Connect to Tendermint RPC server.
    fn connect(&self, address: &SocketAddr, request_rx: mpsc::UnboundedReceiver<Message>) {
        let request = Request {
            url: format!("ws://{}", address).parse().unwrap(),
            extra_headers: None,
        };

        let inner = self.inner.clone();
        let task = tokio_tungstenite::connect_async(request).and_then(move |(stream, _)| {
            info!("Connected with Tendermint RPC server");

            let inner = inner.clone();
            let (sink, stream) = stream.split();
            let forwarder = request_rx
                .map_err(|_| tungstenite::Error::ConnectionClosed(None))
                .forward(sink)
                .discard();
            let processor = stream
                .for_each(move |message| {
                    if let Message::Text(data) = message {
                        // Text message, deserialize as JSON-RPC response.
                        if let Ok(output) = serde_json::from_str::<Output>(&data) {
                            let call_id = match output {
                                Output::Success(ref success) => success.id.clone(),
                                Output::Failure(ref failure) => failure.id.clone(),
                            };

                            if let Id::Num(call_id) = call_id {
                                let mut subscriptions = inner.subscriptions.lock().unwrap();
                                let subscriber = subscriptions.remove(&(call_id as usize));
                                match subscriber {
                                    Some(Subscriber::OneShot(tx)) => {
                                        drop(tx.send(output));
                                    }
                                    Some(Subscriber::Stream(tx)) => {
                                        drop(tx.unbounded_send(output));
                                        subscriptions
                                            .insert(call_id as usize, Subscriber::Stream(tx));
                                    }
                                    None => {
                                        warn!("Received unsolicited response: {:?}", data);
                                    }
                                }
                            } else {
                                warn!("Received message with invalid identifier: {:?}", data);
                            }
                        } else {
                            warn!("Received malformed message: {:?}", data);
                        }
                    }

                    Ok(())
                })
                .discard();

            // Wait for either the forwarder or event processor to complete.
            forwarder.select(processor).then(|_| Ok(()))
        });

        self.inner.environment.spawn(task.discard());
    }

    /// Perform a raw JSON-RPC call or subscription.
    fn raw_rpc_call(&self, method: &str, params: Params, subscriber: Subscriber) {
        let call_id = self.inner.last_call_id.fetch_add(1, Ordering::SeqCst);
        self.inner
            .subscriptions
            .lock()
            .unwrap()
            .insert(call_id, subscriber);

        let request = MethodCall {
            jsonrpc: Some(Version::V2),
            method: method.into(),
            params: Some(params),
            id: Id::Num(call_id as u64),
        };

        self.inner
            .request_tx
            .unbounded_send(Message::Text(serde_json::to_string(&request).unwrap()))
            .unwrap();
    }

    /// Perform a JSON-RPC call.
    fn rpc_call(&self, method: &str, params: Params) -> BoxFuture<Output> {
        let (tx, rx) = oneshot::channel();
        self.raw_rpc_call(method, params, Subscriber::OneShot(tx));

        rx.map_err(|error| error.into()).into_box()
    }

    /// Perform a JSON-RPC subscription.
    fn rpc_subscribe(&self, method: &str, params: Params) -> BoxStream<Output> {
        let (tx, rx) = mpsc::unbounded();
        self.raw_rpc_call(method, params, Subscriber::Stream(tx));

        rx.map_err(|_error| Error::new("channel closed")).into_box()
    }

    /// Perform a `broadcast_tx_sync` RPC call.
    ///
    /// Returns with the response from CheckTx.
    pub fn broadcast_tx_sync(&self, tx: &[u8]) -> BoxFuture<()> {
        let encoded_tx = base64::encode(tx);
        let mut params = serde_json::Map::new();
        params.insert("tx".into(), serde_json::Value::String(encoded_tx));

        self.rpc_call("broadcast_tx_sync", Params::Map(params))
            .and_then(|output| match output {
                Output::Success(_) => Ok(()),
                Output::Failure(failure) => Err(Error::new(failure.error.message)),
            })
            .into_box()
    }

    /// Subscribe to events emitted by Tendermint.
    pub fn subscribe(&self, query: &str) -> BoxStream<Output> {
        let mut params = serde_json::Map::new();
        params.insert("query".into(), serde_json::Value::String(query.into()));

        self.rpc_subscribe("subscribe", Params::Map(params))
    }
}
