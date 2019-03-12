//! Worker side of the worker-host protocol.
use std::{
    collections::HashMap,
    io::{BufReader, BufWriter, Read, Write},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crossbeam::channel;
use failure::Fallible;
use io_context::Context;
use serde_cbor::{self, SerializerOptions};
use slog::Logger;

use crate::{
    common::{crypto::hash::Hash, logger::get_logger},
    dispatcher::Dispatcher,
    rak::RAK,
    storage::CAS,
    tracing,
    types::{Body, Message, MessageType},
};

#[cfg(not(target_env = "sgx"))]
pub type Stream = ::std::os::unix::net::UnixStream;
#[cfg(target_env = "sgx")]
pub type Stream = ::std::net::TcpStream;

/// Maximum message size.
const MAX_MESSAGE_SIZE: usize = 104_857_600; // 100MB

#[derive(Debug, Fail)]
enum ProtocolError {
    #[fail(display = "message too large")]
    MessageTooLarge,
    #[fail(display = "method not supported")]
    MethodNotSupported,
    #[fail(display = "invalid response")]
    InvalidResponse,
}

/// Worker part of the worker-host protocol.
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
    /// Stream to the worker host.
    stream: Stream,
    /// Outgoing request identifier generator.
    last_request_id: AtomicUsize,
    /// Pending outgoing requests.
    pending_out_requests: Mutex<HashMap<u64, channel::Sender<Body>>>,
}

impl Protocol {
    /// Create a new protocol handler instance.
    pub fn new(stream: Stream, rak: Arc<RAK>, dispatcher: Arc<Dispatcher>) -> Self {
        let logger = get_logger("runtime/protocol");

        Self {
            logger,
            rak,
            dispatcher,
            outgoing_mutex: Mutex::new(()),
            stream,
            last_request_id: AtomicUsize::new(0),
            pending_out_requests: Mutex::new(HashMap::new()),
        }
    }

    /// Start the protocol handler loop.
    pub fn start(&self) {
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
    pub fn make_request(&self, ctx: Context, body: Body) -> Fallible<Body> {
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

        Ok(rx.recv()?)
    }

    /// Send an async response to a previous request back to the worker host.
    pub fn send_response(&self, id: u64, body: Body) -> Fallible<()> {
        self.encode_message(Message {
            id,
            body,
            span_context: vec![],
            message_type: MessageType::Response,
        })
    }

    fn decode_message<R: Read>(&self, mut reader: R) -> Fallible<Message> {
        let length = reader.read_u32::<BigEndian>()? as usize;
        if length > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::MessageTooLarge.into());
        }

        // TODO: Avoid allocations.
        let mut buffer = vec![0; length];
        reader.read_exact(&mut buffer)?;

        Ok(serde_cbor::from_slice(&buffer)?)
    }

    fn encode_message(&self, message: Message) -> Fallible<()> {
        let _guard = self.outgoing_mutex.lock().unwrap();
        let mut writer = BufWriter::new(&self.stream);

        let buffer = serde_cbor::to_vec_with_options(
            &message,
            &SerializerOptions {
                packed: false,
                enum_as_map: true,
                self_describe: false,
            },
        )?;
        if buffer.len() > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::MessageTooLarge.into());
        }

        writer.write_u32::<BigEndian>(buffer.len() as u32)?;
        writer.write_all(&buffer)?;

        Ok(())
    }

    fn handle_message<R: Read>(&self, reader: R) -> Fallible<()> {
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
                    Err(error) => Body::Error {
                        message: format!("{}", error),
                    },
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
                        warn!(self.logger, "Received response message for unknown request"; "msg_id" => message.id)
                    }
                }
            }
            _ => warn!(self.logger, "Received a malformed message"),
        }

        Ok(())
    }

    fn handle_request(&self, ctx: Context, id: u64, request: Body) -> Fallible<Option<Body>> {
        match request {
            Body::WorkerPingRequest {} => Ok(Some(Body::Empty {})),
            Body::WorkerShutdownRequest {} => {
                info!(self.logger, "Received worker shutdown request");
                Err(ProtocolError::MethodNotSupported.into())
            }
            Body::WorkerAbortRequest {} => {
                info!(self.logger, "Received worker abort request");
                Err(ProtocolError::MethodNotSupported.into())
            }
            #[cfg(target_env = "sgx")]
            Body::WorkerCapabilityTEERakReportRequest { target_info } => {
                // Initialize the runtime attestation key.
                info!(self.logger, "Initializing the runtime attestation key");
                let (rak_pub, report) = self.rak.init(target_info);

                let report: &[u8] = report.as_ref();
                let report = report.to_vec();

                Ok(Some(Body::WorkerCapabilityTEERakReportResponse {
                    rak_pub,
                    report,
                }))
            }
            #[cfg(target_env = "sgx")]
            Body::WorkerCapabilityTEERakAvrRequest { avr } => {
                info!(
                    self.logger,
                    "Configuring AVR for the runtime attestation key binding"
                );
                self.rak.set_avr(avr)?;
                Ok(Some(Body::WorkerCapabilityTEERakAvrResponse {}))
            }
            req @ Body::WorkerRPCCallRequest { .. } => {
                self.dispatcher.queue_request(ctx, id, req)?;
                Ok(None)
            }
            req @ Body::WorkerRuntimeCallBatchRequest { .. } => {
                self.dispatcher.queue_request(ctx, id, req)?;
                Ok(None)
            }
            req => {
                warn!(self.logger, "Received unsupported request"; "req" => format!("{:?}", req));
                Err(ProtocolError::MethodNotSupported.into())
            }
        }
    }
}

/// CAS implementation which forwards all requests to the worker host.
pub struct ProtocolCAS {
    ctx: Arc<Context>,
    protocol: Arc<Protocol>,
}

impl ProtocolCAS {
    pub fn new(ctx: Context, protocol: Arc<Protocol>) -> Self {
        Self {
            ctx: ctx.freeze(),
            protocol,
        }
    }
}

impl CAS for ProtocolCAS {
    fn get(&self, key: Hash) -> Fallible<Vec<u8>> {
        let ctx = Context::create_child(&self.ctx);

        match self
            .protocol
            .make_request(ctx, Body::HostStorageGetRequest { key })
        {
            Ok(Body::HostStorageGetResponse { value }) => Ok(value),
            Ok(_) => Err(ProtocolError::InvalidResponse.into()),
            Err(error) => Err(error),
        }
    }

    fn insert(&self, _value: Vec<u8>, _expiry: u64) -> Fallible<Hash> {
        // The protocol only supports a read-only CAS interface. Insert operations
        // must be recorded and returned as part of the computed batch.
        panic!("protocol does not support CAS insert operations");
    }
}
