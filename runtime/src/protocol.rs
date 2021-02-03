//! Runtime side of the worker-host protocol.
use std::{
    collections::HashMap,
    io::{BufReader, BufWriter, Read, Write},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crossbeam::channel;
use io_context::Context;
use slog::Logger;
use thiserror::Error;

use crate::{
    common::{cbor, logger::get_logger, namespace::Namespace, version::Version},
    dispatcher::Dispatcher,
    rak::RAK,
    storage::KeyValue,
    tracing,
    types::{Body, Error, Message, MessageType},
    BUILD_INFO,
};

#[cfg(not(target_env = "sgx"))]
pub type Stream = ::std::os::unix::net::UnixStream;
#[cfg(target_env = "sgx")]
pub type Stream = ::std::net::TcpStream;

/// Maximum message size.
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16MiB

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("message too large")]
    MessageTooLarge,
    #[error("method not supported")]
    MethodNotSupported,
    #[error("invalid response")]
    InvalidResponse,
    #[error("attestation required")]
    #[allow(unused)]
    AttestationRequired,
    #[error("runtime id not set")]
    RuntimeIDNotSet,
}

/// Runtime part of the runtime host protocol.
pub struct Protocol {
    /// Logger.
    logger: Logger,
    /// Runtime attestation key.
    #[cfg_attr(not(target_env = "sgx"), allow(unused))]
    rak: Arc<RAK>,
    /// Incoming request dispatcher.
    dispatcher: Arc<Dispatcher>,
    /// Mutex for sending outgoing messages.
    outgoing_mutex: Mutex<()>,
    /// Stream to the runtime host.
    stream: Stream,
    /// Outgoing request identifier generator.
    last_request_id: AtomicUsize,
    /// Pending outgoing requests.
    pending_out_requests: Mutex<HashMap<u64, channel::Sender<Body>>>,
    /// Runtime identifier.
    runtime_id: Mutex<Option<Namespace>>,
    /// Runtime version.
    runtime_version: Version,
}

impl Protocol {
    /// Create a new protocol handler instance.
    pub fn new(
        stream: Stream,
        rak: Arc<RAK>,
        dispatcher: Arc<Dispatcher>,
        runtime_version: Version,
    ) -> Self {
        let logger = get_logger("runtime/protocol");

        Self {
            logger,
            rak,
            dispatcher,
            outgoing_mutex: Mutex::new(()),
            stream,
            last_request_id: AtomicUsize::new(0),
            pending_out_requests: Mutex::new(HashMap::new()),
            runtime_id: Mutex::new(None),
            runtime_version: runtime_version,
        }
    }

    /// Return the runtime identifier for this worker.
    ///
    /// # Panics
    ///
    /// Panics, if the runtime identifier is not set.
    pub fn get_runtime_id(self: &Protocol) -> Namespace {
        self.runtime_id
            .lock()
            .unwrap()
            .expect("runtime_id should be set")
    }

    /// Start the protocol handler loop.
    pub fn start(self: &Arc<Protocol>) {
        info!(self.logger, "Starting protocol handler");
        let mut reader = BufReader::new(&self.stream);

        'recv: loop {
            match self.handle_message(&mut reader) {
                Err(error) => {
                    error!(self.logger, "Failed to handle message"; "err" => %error);
                    break 'recv;
                }
                Ok(()) => {}
            }
        }

        info!(self.logger, "Protocol handler is terminating");
    }

    /// Make a new request to the worker host and wait for the response.
    pub fn make_request(&self, ctx: Context, body: Body) -> Result<Body> {
        let id = self.last_request_id.fetch_add(1, Ordering::SeqCst) as u64;
        let span_context = tracing::get_span_context(&ctx).unwrap_or(&vec![]).clone();
        let message = Message {
            id,
            body,
            span_context,
            message_type: MessageType::Request,
        };

        // Create a response channel and register an outstanding pending request.
        let (tx, rx) = channel::bounded(1);
        {
            let mut pending_requests = self.pending_out_requests.lock().unwrap();
            pending_requests.insert(id, tx);
        }

        // Write message to stream and wait for the response.
        self.encode_message(message)?;

        match rx.recv()? {
            Body::Error(Error { message, .. }) => Err(anyhow!("{}", message)),
            body => Ok(body),
        }
    }

    /// Send an async response to a previous request back to the worker host.
    pub fn send_response(&self, id: u64, body: Body) -> Result<()> {
        self.encode_message(Message {
            id,
            body,
            span_context: vec![],
            message_type: MessageType::Response,
        })
    }

    fn decode_message<R: Read>(&self, mut reader: R) -> Result<Message> {
        let length = reader.read_u32::<BigEndian>()? as usize;
        if length > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::MessageTooLarge.into());
        }

        // TODO: Avoid allocations.
        let mut buffer = vec![0; length];
        reader.read_exact(&mut buffer)?;

        Ok(cbor::from_slice(&buffer)?)
    }

    fn encode_message(&self, message: Message) -> Result<()> {
        let _guard = self.outgoing_mutex.lock().unwrap();
        let mut writer = BufWriter::new(&self.stream);

        let buffer = cbor::to_vec(&message);
        if buffer.len() > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::MessageTooLarge.into());
        }

        writer.write_u32::<BigEndian>(buffer.len() as u32)?;
        writer.write_all(&buffer)?;

        Ok(())
    }

    fn handle_message<R: Read>(self: &Arc<Protocol>, reader: R) -> Result<()> {
        let message = self.decode_message(reader)?;

        match message.message_type {
            MessageType::Request => {
                // Incoming request.
                let id = message.id;
                let mut ctx = Context::background();
                tracing::add_span_context(&mut ctx, message.span_context);

                let body = match self.handle_request(ctx, id, message.body) {
                    Ok(Some(result)) => result,
                    Ok(None) => {
                        // A message will be sent later by another thread so there
                        // is no need to do anything more.
                        return Ok(());
                    }
                    Err(error) => Body::Error(Error::new("dispatcher", 1, &format!("{}", error))),
                };

                // Send response back.
                self.encode_message(Message {
                    id,
                    message_type: MessageType::Response,
                    body,
                    span_context: vec![],
                })?;
            }
            MessageType::Response => {
                // Response to our request.
                let response_sender = {
                    let mut pending_requests = self.pending_out_requests.lock().unwrap();
                    pending_requests.remove(&message.id)
                };

                match response_sender {
                    Some(response_sender) => {
                        if let Err(error) = response_sender.try_send(message.body) {
                            warn!(self.logger, "Unable to deliver response to local handler"; "err" => %error);
                        }
                    }
                    None => {
                        warn!(self.logger, "Received response message for unknown request"; "msg_id" => message.id);
                    }
                }
            }
            _ => warn!(self.logger, "Received a malformed message"),
        }

        Ok(())
    }

    fn handle_request(
        self: &Arc<Protocol>,
        ctx: Context,
        id: u64,
        request: Body,
    ) -> Result<Option<Body>> {
        match request {
            Body::RuntimeInfoRequest {
                runtime_id,
                consensus_backend,
                consensus_protocol_version,
            } => {
                info!(self.logger, "Received host environment information";
                    "runtime_id" => ?runtime_id,
                    "consensus_backend" => consensus_backend,
                    "consensus_protocol_version" => consensus_protocol_version,
                );
                // TODO: Verify consensus backend/protocol compatibility.

                // Store the passed runtime ID.
                *self.runtime_id.lock().unwrap() = Some(runtime_id);

                self.dispatcher.start(self.clone());

                Ok(Some(Body::RuntimeInfoResponse {
                    protocol_version: BUILD_INFO.protocol_version.into(),
                    runtime_version: self.runtime_version.into(),
                }))
            }
            Body::RuntimePingRequest {} => Ok(Some(Body::Empty {})),
            Body::RuntimeShutdownRequest {} => {
                info!(self.logger, "Received worker shutdown request");
                Err(ProtocolError::MethodNotSupported.into())
            }
            req @ Body::RuntimeAbortRequest {} => {
                info!(self.logger, "Received worker abort request");
                self.can_handle_runtime_requests()?;
                self.dispatcher.abort_and_wait(ctx, id, req)?;
                info!(self.logger, "Handled worker abort request");
                Ok(Some(Body::RuntimeAbortResponse {}))
            }
            #[cfg(target_env = "sgx")]
            Body::RuntimeCapabilityTEERakInitRequest { target_info } => {
                info!(self.logger, "Initializing the runtime attestation key");
                self.rak.init_rak(target_info)?;
                Ok(Some(Body::RuntimeCapabilityTEERakInitResponse {}))
            }
            #[cfg(target_env = "sgx")]
            Body::RuntimeCapabilityTEERakReportRequest {} => {
                // Initialize the RAK report (for attestation).
                info!(
                    self.logger,
                    "Initializing the runtime attestation key report"
                );
                let (rak_pub, report, nonce) = self.rak.init_report();

                let report: &[u8] = report.as_ref();
                let report = report.to_vec();

                Ok(Some(Body::RuntimeCapabilityTEERakReportResponse {
                    rak_pub,
                    report,
                    nonce,
                }))
            }
            #[cfg(target_env = "sgx")]
            Body::RuntimeCapabilityTEERakAvrRequest { avr } => {
                info!(
                    self.logger,
                    "Configuring AVR for the runtime attestation key binding"
                );
                self.rak.set_avr(avr)?;
                Ok(Some(Body::RuntimeCapabilityTEERakAvrResponse {}))
            }
            req @ Body::RuntimeRPCCallRequest { .. } => {
                self.can_handle_runtime_requests()?;
                self.dispatcher.queue_request(ctx, id, req)?;
                Ok(None)
            }
            req @ Body::RuntimeLocalRPCCallRequest { .. } => {
                self.can_handle_runtime_requests()?;
                self.dispatcher.queue_request(ctx, id, req)?;
                Ok(None)
            }
            req @ Body::RuntimeCheckTxBatchRequest { .. } => {
                self.can_handle_runtime_requests()?;
                self.dispatcher.queue_request(ctx, id, req)?;
                Ok(None)
            }
            req @ Body::RuntimeExecuteTxBatchRequest { .. } => {
                self.can_handle_runtime_requests()?;
                self.dispatcher.queue_request(ctx, id, req)?;
                Ok(None)
            }
            req @ Body::RuntimeKeyManagerPolicyUpdateRequest { .. } => {
                info!(self.logger, "Received key manager policy update request");
                self.can_handle_runtime_requests()?;
                self.dispatcher.queue_request(ctx, id, req)?;
                Ok(None)
            }
            req @ Body::RuntimeQueryRequest { .. } => {
                self.can_handle_runtime_requests()?;
                self.dispatcher.queue_request(ctx, id, req)?;
                Ok(None)
            }
            req => {
                warn!(self.logger, "Received unsupported request"; "req" => format!("{:?}", req));
                Err(ProtocolError::MethodNotSupported.into())
            }
        }
    }

    fn can_handle_runtime_requests(&self) -> Result<()> {
        if self.runtime_id.lock().unwrap().is_none() {
            return Err(ProtocolError::RuntimeIDNotSet.into());
        }

        #[cfg(target_env = "sgx")]
        {
            if self.rak.avr().is_none() {
                return Err(ProtocolError::AttestationRequired.into());
            }
        }

        Ok(())
    }
}

/// Untrusted key/value store which stores arbitrary binary key/value pairs
/// on the worker host.
///
/// Care MUST be taken to not trust this interface at all.  The worker host
/// is capable of doing whatever it wants including but not limited to,
/// hiding data, tampering with keys/values, ignoring writes, replaying
/// past values, etc.
pub struct ProtocolUntrustedLocalStorage {
    ctx: Arc<Context>,
    protocol: Arc<Protocol>,
}

impl ProtocolUntrustedLocalStorage {
    pub fn new(ctx: Context, protocol: Arc<Protocol>) -> Self {
        Self {
            ctx: ctx.freeze(),
            protocol,
        }
    }
}

impl KeyValue for ProtocolUntrustedLocalStorage {
    fn get(&self, key: Vec<u8>) -> Result<Vec<u8>> {
        let ctx = Context::create_child(&self.ctx);

        match self
            .protocol
            .make_request(ctx, Body::HostLocalStorageGetRequest { key })
        {
            Ok(Body::HostLocalStorageGetResponse { value }) => Ok(value),
            Ok(_) => Err(ProtocolError::InvalidResponse.into()),
            Err(error) => Err(error),
        }
    }

    fn insert(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let ctx = Context::create_child(&self.ctx);

        match self
            .protocol
            .make_request(ctx, Body::HostLocalStorageSetRequest { key, value })
        {
            Ok(Body::HostLocalStorageSetResponse {}) => Ok(()),
            Ok(_) => Err(ProtocolError::InvalidResponse.into()),
            Err(error) => Err(error),
        }
    }
}
