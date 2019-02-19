//! Worker-host IPC protocol.
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use log::{error, warn};
use rustracing_jaeger::span::SpanContext;
use std::io::Cursor;
use tokio_codec::Decoder;
use tokio_io::{AsyncRead, AsyncWrite};

use ekiden_core::{
    environment::Environment,
    error::Error,
    futures::{
        prelude::*,
        sync::{mpsc, oneshot},
    },
    tokio::timer::Interval,
};

use super::{
    codec::Codec,
    types::{Body, Message, MessageType},
};

/// Keep-alive interval for connections (in seconds).
const PROTOCOL_KEEPALIVE_INTERVAL: u64 = 1;

/// Request handler.
pub trait Handler: Sync + Send {
    /// Handle given request and return a response.
    fn handle(&self, ctx: Option<SpanContext>, body: Body) -> BoxFuture<Body>;
}

impl<T: ?Sized + Handler> Handler for Arc<T> {
    fn handle(&self, ctx: Option<SpanContext>, body: Body) -> BoxFuture<Body> {
        Handler::handle(&**self, ctx, body)
    }
}

/// Shutdown notification channel.
///
/// A message will be sent when the other end shuts down communication.
pub type ShutdownNotify = oneshot::Receiver<()>;

struct Inner {
    /// Environment.
    environment: Arc<Environment>,
    /// Outgoing protocol message channel.
    message_sender: mpsc::Sender<Message>,
    /// Request identifier generator.
    last_request_id: AtomicUsize,
    /// Pending requests.
    pending_requests: Mutex<HashMap<u64, oneshot::Sender<Body>>>,
    /// Incoming request handler.
    request_handler: Arc<Handler>,
}

/// Worker protocol implementation.
pub struct Protocol {
    inner: Arc<Inner>,
}

impl Protocol {
    /// Creates a new worker-host protocol instance over the given socket.
    ///
    /// Note that the underlying socket must be reliable as the protocol will not
    /// handle lost messages.
    pub fn new<T>(
        environment: Arc<Environment>,
        socket: T,
        request_handler: Arc<Handler>,
    ) -> (Self, ShutdownNotify)
    where
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (send_error_sender, send_error_receiver) = oneshot::channel();
        let (recv_error_sender, recv_error_receiver) = oneshot::channel();
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let (message_sender, message_receiver) = mpsc::channel(10);
        let (sink, stream) = Codec::new().framed(socket).split();

        let inner = Arc::new(Inner {
            environment: environment.clone(),
            message_sender,
            last_request_id: AtomicUsize::new(0),
            pending_requests: Mutex::new(HashMap::new()),
            request_handler,
        });

        // Spawn shutdown signal dispatcher. If either the sending or the receiving
        // tasks generate an error, we emit the shutdown signal which will terminate
        // the protocol instance.
        environment.spawn(
            future::select_all(vec![send_error_receiver, recv_error_receiver])
                .map(|_| {
                    // Either the sender or the receiver encountered an error. Send the
                    // shutdown signal which may fail if the receiver has already been
                    // dropped in which case the shutdown signal is ignored.
                    drop(shutdown_sender.send(()));
                })
                .discard(),
        );

        // Spawn message sender.
        environment.spawn(
            sink.send_all(message_receiver.map_err(|_| Error::new("channel closed")))
                .map_err(|error| {
                    error!("Failed to send message: {:?}", error);
                    // Send may fail if the protocol has already shut down.
                    drop(send_error_sender.send(()));

                    error
                })
                .discard(),
        );

        // Spawn keep-alive task.
        let shared_inner = inner.clone();
        environment.spawn(
            Interval::new_interval(Duration::from_secs(PROTOCOL_KEEPALIVE_INTERVAL))
                .map_err(|_| ())
                .for_each(move |_| {
                    shared_inner
                        .message_sender
                        .clone()
                        .send(Message {
                            id: 0,
                            message_type: MessageType::KeepAlive,
                            body: Body::Empty {},
                            span_context: vec![],
                        })
                        .discard()
                })
                .into_box(),
        );

        // Spawn incoming message processor.
        let shared_inner = inner.clone();
        environment.spawn(
            stream
                .for_each(move |message| {
                    // Spawn a new task to process the request.
                    let shared_inner = shared_inner.clone();
                    spawn(future::lazy(move || {
                        match message.message_type {
                            MessageType::Request => {
                                // Incoming request.
                                let shared_inner = shared_inner.clone();
                                let id = message.id;

                                // Extract the span context, if it is present in the message.
                                let mut ctx: Option<SpanContext> = None;
                                if !message.span_context.is_empty() {
                                    let mut span_buf = Cursor::new(message.span_context);
                                    match SpanContext::extract_from_binary(&mut span_buf) {
                                        Ok(context) => ctx = context,
                                        Err(_) => warn!("Failed to extract span from binary span {:?}", span_buf),
                                    };
                                }

                                return shared_inner
                                    .request_handler
                                    .handle(ctx, message.body)
                                    .then(move |result| {
                                        let body = match result {
                                            Ok(value) => value,
                                            Err(error) => Body::Error {
                                                message: error.message,
                                            },
                                        };

                                        // Send response back.
                                        shared_inner.message_sender.clone().send(Message {
                                            id,
                                            message_type: MessageType::Response,
                                            body,
                                            span_context: vec![],
                                        })
                                    })
                                    .map(|_| ())
                                    .map_err(|error| {
                                        warn!("Failed to handle request: {:?}", error);
                                    })
                                    .into_box();
                            }
                            MessageType::Response => {
                                // Response to our request.
                                let response_sender = {
                                    let mut pending_requests =
                                        shared_inner.pending_requests.lock().unwrap();
                                    pending_requests.remove(&message.id)
                                };

                                match response_sender {
                                    Some(response_sender) => {
                                        if let Err(_) = response_sender.send(message.body) {
                                            warn!("Unable to deliver response to local handler");
                                        }
                                    }
                                    None => warn!("Received response message but no request with id {} is outstanding", message.id),
                                }
                            }
                            MessageType::KeepAlive => {}
                            _ => warn!("Received a malformed message"),
                        }

                        future::ok(()).into_box()
                    }));

                    future::ok(()).into_box()
                })
                .map_err(|error| {
                    error!(
                        "Unhandled error while decoding incoming requests: {:?}",
                        error
                    );
                    // Send may fail if the protocol has already shut down.
                    drop(recv_error_sender.send(()));

                    error
                })
                .discard(),
        );

        (Protocol { inner }, shutdown_receiver)
    }

    pub(crate) fn make_request(&self, ctx: Option<SpanContext>, body: Body) -> BoxFuture<Body> {
        let id = self.inner.last_request_id.fetch_add(1, Ordering::SeqCst) as u64;
        let mut span_buf: Cursor<Vec<u8>> = Cursor::new(vec![]);
        match ctx.clone() {
            Some(sc) => match sc.inject_to_binary(&mut span_buf) {
                Ok(_) => (),
                Err(err) => warn!("Error while injecting to binary: {}", err),
            },
            None => (),
        }

        let message = Message {
            id,
            body,
            message_type: MessageType::Request,
            span_context: span_buf.get_ref().to_vec(),
        };

        // Create a response channel and register an outstanding pending request.
        let (response_sender, response_receiver) = oneshot::channel();
        {
            let mut pending_requests = self.inner.pending_requests.lock().unwrap();
            pending_requests.insert(id, response_sender);
        }

        self.inner
            .message_sender
            .clone()
            .send(message)
            .map_err(|_| Error::new("unable to send message"))
            .and_then(move |_| response_receiver.map_err(|_| Error::new("channel closed")))
            .and_then(|body| match body {
                Body::Error { message } => Err(Error::new(message)),
                body => Ok(body),
            })
            .into_box()
    }

    pub(crate) fn environment(&self) -> Arc<Environment> {
        self.inner.environment.clone()
    }
}

#[cfg(test)]
mod tests {
    extern crate grpcio;
    extern crate tokio_uds;

    use rustracing_jaeger::span::SpanContext;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use ekiden_core::{
        environment::GrpcEnvironment,
        futures::{block_on, prelude::*},
    };

    use super::{super::types::Body, Handler, Protocol};

    struct EchoHandler {
        calls: AtomicUsize,
    }

    impl EchoHandler {
        fn new() -> Self {
            EchoHandler {
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl Handler for EchoHandler {
        fn handle(&self, _: Option<SpanContext>, body: Body) -> BoxFuture<Body> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            future::ok(body).into_box()
        }
    }

    #[test]
    fn test_echo_request_response() {
        let grpc_environment = grpcio::EnvBuilder::new().build();
        let environment = Arc::new(GrpcEnvironment::new(grpc_environment));

        let handler_a = Arc::new(EchoHandler::new());
        let handler_b = Arc::new(EchoHandler::new());

        let (socket_a, socket_b) = tokio_uds::UnixStream::pair().unwrap();
        let (protocol_a, _) = Protocol::new(environment.clone(), socket_a, handler_a.clone());
        let (protocol_b, _) = Protocol::new(environment.clone(), socket_b, handler_b.clone());

        block_on(
            environment.clone(),
            protocol_a.make_request(None, Body::Empty {}),
        )
        .unwrap();
        assert_eq!(handler_a.calls.load(Ordering::SeqCst), 0);
        assert_eq!(handler_b.calls.load(Ordering::SeqCst), 1);

        block_on(
            environment.clone(),
            protocol_b.make_request(None, Body::Empty {}),
        )
        .unwrap();
        assert_eq!(handler_a.calls.load(Ordering::SeqCst), 1);
        assert_eq!(handler_b.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_big_message() {
        let grpc_environment = grpcio::EnvBuilder::new().build();
        let environment = Arc::new(GrpcEnvironment::new(grpc_environment));

        let handler_a = Arc::new(EchoHandler::new());
        let handler_b = Arc::new(EchoHandler::new());

        let (socket_a, socket_b) = tokio_uds::UnixStream::pair().unwrap();
        let (protocol_a, _) = Protocol::new(environment.clone(), socket_a, handler_a.clone());
        let (_protocol_b, _) = Protocol::new(environment.clone(), socket_b, handler_b.clone());

        // Generate a large request.
        let request = Body::WorkerRPCCallRequest {
            request: vec![42; 2_000_000],
        };
        block_on(environment.clone(), protocol_a.make_request(None, request)).unwrap();
        assert_eq!(handler_a.calls.load(Ordering::SeqCst), 0);
        assert_eq!(handler_b.calls.load(Ordering::SeqCst), 1);
    }
}
