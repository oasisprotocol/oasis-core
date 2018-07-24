use std::sync::Arc;
#[cfg(not(target_env = "sgx"))]
use std::sync::Mutex;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutex as Mutex;

use protobuf;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_cbor;

use ekiden_common::error::Error;
#[cfg(not(target_env = "sgx"))]
use ekiden_common::error::Result;
use ekiden_common::futures::prelude::*;
#[cfg(not(target_env = "sgx"))]
use ekiden_common::futures::sync::{mpsc, oneshot};
use ekiden_enclave_common::quote::MrEnclave;
use ekiden_rpc_common::api;

use super::backend::RpcClientBackend;
use super::secure_channel::SecureChannelContext;

/// Commands sent to the processing task.
#[cfg(not(target_env = "sgx"))]
enum Command {
    /// Make a remote method call.
    Call(api::PlainClientRequest, oneshot::Sender<Result<Vec<u8>>>),
    /// Initialize secure channel.
    InitSecureChannel(oneshot::Sender<Result<()>>),
    /// Close secure channel.
    CloseSecureChannel(oneshot::Sender<Result<()>>),
}

/// Contract client context used for async calls.
struct RpcClientContext<Backend: RpcClientBackend + 'static> {
    /// Backend handling network communication.
    backend: Arc<Backend>,
    /// Contract MRENCLAVE.
    mr_enclave: MrEnclave,
    /// Secure channel context.
    secure_channel: SecureChannelContext,
    /// Client authentication required flag.
    client_authentication: bool,
}

/// Helper for running client commands.
#[cfg(not(target_env = "sgx"))]
fn run_command<F, R>(cmd: F, response_tx: oneshot::Sender<Result<R>>) -> BoxFuture<()>
where
    F: Future<Item = R, Error = Error> + Send + 'static,
    R: Send + 'static,
{
    Box::new(cmd.then(move |result| {
        // Send command result back to response channel, ignoring any errors, which
        // may be due to closing of the other end of the response channel.
        response_tx.send(result).or(Ok(()))
    }))
}

impl<Backend: RpcClientBackend + 'static> RpcClientContext<Backend> {
    /// Process commands sent via the command channel.
    ///
    /// This method returns a future, which keeps processing all commands received
    /// via the `request_rx` channel. It should be spawned as a separate task.
    ///
    /// Processing commands in this way ensures that all client requests are processed
    /// in order, with no interleaving of requests, regardless of how the futures
    /// executor is implemented.
    #[cfg(not(target_env = "sgx"))]
    fn process_commands(
        context: Arc<Mutex<Self>>,
        request_rx: mpsc::UnboundedReceiver<Command>,
    ) -> BoxFuture<()> {
        // Process all requests in order. The stream processing ends when the sender
        // handle (request_tx) in RpcClient is dropped.
        let result = request_rx
            .map_err(|_| Error::new("Command channel closed"))
            .for_each(move |command| -> BoxFuture<()> {
                match command {
                    Command::Call(request, response_tx) => {
                        run_command(Self::call_raw(context.clone(), request), response_tx)
                    }
                    Command::InitSecureChannel(response_tx) => {
                        run_command(Self::init_secure_channel(context.clone()), response_tx)
                    }
                    Command::CloseSecureChannel(response_tx) => {
                        run_command(Self::close_secure_channel(context.clone()), response_tx)
                    }
                }
            });

        Box::new(result)
    }

    /// Call a contract method.
    fn call_raw(
        context: Arc<Mutex<Self>>,
        plain_request: api::PlainClientRequest,
    ) -> BoxFuture<Vec<u8>> {
        // Ensure secure channel is initialized before making the request.
        let init_sc = Self::init_secure_channel(context.clone());

        // Context moved into the closure (renamed for clarity).
        let shared_context = context;

        let result = init_sc.and_then(move |_| -> BoxFuture<Vec<u8>> {
            // Clone method for use in later future.
            let cloned_method = plain_request.get_method().to_owned();

            // Prepare the backend call future. This is done in a new scope so that the held
            // lock is released early and we can move shared_context into the next future.
            let backend_call = {
                let mut context = shared_context.lock().unwrap();

                let mut client_request = api::ClientRequest::new();
                if context.secure_channel.must_encrypt() {
                    // Encrypt request.
                    client_request.set_encrypted_request(match context
                        .secure_channel
                        .create_request_box(&plain_request)
                    {
                        Ok(request) => request,
                        Err(error) => return Box::new(future::err(error)),
                    });
                } else {
                    // Plain-text request.
                    client_request.set_plain_request(plain_request);
                }

                // Invoke the backend to make the actual request.
                context.backend.call(client_request)
            };

            // After the backend call is done, handle the response.
            let result = backend_call.and_then(move |mut client_response| -> BoxFuture<Vec<u8>> {
                let mut plain_response = {
                    let mut context = shared_context.lock().unwrap();

                    let mut plain_response = {
                        if client_response.has_encrypted_response() {
                            // Encrypted response.
                            match context
                                .secure_channel
                                .open_response_box(&client_response.get_encrypted_response())
                            {
                                Ok(response) => response,
                                Err(error) => return Box::new(future::err(error)),
                            }
                        } else {
                            // Plain-text response.
                            client_response.take_plain_response()
                        }
                    };

                    if context.secure_channel.must_encrypt()
                        && !client_response.has_encrypted_response()
                    {
                        match plain_response.get_code() {
                            api::PlainClientResponse_Code::ERROR_SECURE_CHANNEL => {
                                // Request the secure channel to be reset.
                                // NOTE: This opens us up to potential adversarial interference as an
                                //       adversarial compute node can force the channel to be reset by
                                //       crafting a non-authenticated response. But a compute node can
                                //       always deny service or prevent the secure channel from being
                                //       established in the first place, so this is not really an issue.
                                if cloned_method != api::METHOD_CHANNEL_INIT {
                                    context.secure_channel.close();

                                    // Channel will reset on the next request.
                                    return Box::new(future::err(Error::new(
                                        "Secure channel closed",
                                    )));
                                }
                            }
                            _ => {}
                        }

                        return Box::new(future::err(Error::new(
                            "Contract returned plain response for encrypted request",
                        )));
                    }

                    plain_response
                };

                // Validate response code.
                match plain_response.get_code() {
                    api::PlainClientResponse_Code::SUCCESS => {}
                    _ => {
                        // Deserialize error.
                        let mut error: api::Error = {
                            match protobuf::parse_from_bytes(&plain_response.take_payload()) {
                                Ok(error) => error,
                                _ => return Box::new(future::err(Error::new("Unknown error"))),
                            }
                        };

                        return Box::new(future::err(Error::new(error.get_message())));
                    }
                };

                Box::new(future::ok(plain_response.take_payload()))
            });

            Box::new(result)
        });

        Box::new(result)
    }

    /// Call a contract method.
    fn call<Rq, Rs>(context: Arc<Mutex<Self>>, method: &str, request: Rq) -> BoxFuture<Rs>
    where
        Rq: Serialize,
        Rs: DeserializeOwned + Send + 'static,
    {
        // Create a request.
        let mut plain_request = api::PlainClientRequest::new();
        plain_request.set_method(method.to_owned());
        match serde_cbor::to_vec(&request) {
            Ok(payload) => plain_request.set_payload(payload),
            Err(_) => return Box::new(future::err(Error::new("payload serialize failed"))),
        }

        // Make the raw call and then deserialize the response.
        let result = Self::call_raw(context, plain_request)
            .and_then(|plain_response| Ok(serde_cbor::from_slice(&plain_response)?));

        Box::new(result)
    }

    /// Initialize a secure channel with the contract.
    ///
    /// If the channel has already been initialized the future returned by this method
    /// will immediately resolve.
    fn init_secure_channel(context: Arc<Mutex<Self>>) -> BoxFuture<()> {
        // Context moved into the closure (renamed for clarity).
        let shared_context = context;

        let result = future::lazy(move || {
            // Return is futures::future::Either. A is immediate return. B is request.

            let request = {
                let mut context = shared_context.lock().unwrap();

                // If secure channel is already initialized, we don't need to do anything.
                if !context.secure_channel.is_closed() {
                    return future::Either::A(future::ok(()));
                }

                // Reset secure channel.
                match context.secure_channel.reset() {
                    Ok(()) => {}
                    Err(error) => return future::Either::A(future::err(error)),
                };

                let mut request = api::ChannelInitRequest::new();
                request.set_short_term_public_key(
                    context.secure_channel.get_client_public_key().to_vec(),
                );
                request
            };

            // Call remote channel init.
            future::Either::B(
                Self::call::<api::ChannelInitRequest, api::ChannelInitResponse>(
                    shared_context.clone(),
                    api::METHOD_CHANNEL_INIT,
                    request,
                ).and_then(move |response: api::ChannelInitResponse| {
                    // Return is futures::future::Either. A is immediate return. B is request.

                    let request = {
                        let mut context = shared_context.lock().unwrap();
                        let client_authentication = context.client_authentication;

                        // Verify contract identity and set up a secure channel.
                        let iai = match context.secure_channel.setup(
                            response.get_authenticated_short_term_public_key(),
                            client_authentication,
                        ) {
                            Ok(iai) => iai,
                            Err(e) => return future::Either::A(future::err(e)),
                        };

                        // Verify MRENCLAVE.
                        if &iai.mr_enclave != &context.mr_enclave {
                            return future::Either::A(future::err(Error::new(
                                "Secure channel initialization failed: MRENCLAVE mismatch",
                            )));
                        }

                        // TODO: Other access control policy on enclave identity will go here.

                        // If we don't need to authenticate, we're done.
                        if !client_authentication {
                            return future::Either::A(future::ok(()));
                        }

                        let mut request = api::ChannelAuthRequest::new();
                        let credentials = match context.backend.get_credentials() {
                                Some(credentials) => credentials,
                                None => return future::Either::A(future::err(Error::new(
                                    "Channel requires client authentication and backend has no credentials"
                                ))),
                            };
                        let bastpk = match context.secure_channel.get_authentication(
                            &credentials.long_term_private_key,
                            credentials.identity_proof,
                        ) {
                            Ok(bastpk) => bastpk,
                            Err(e) => return future::Either::A(future::err(e)),
                        };
                        request.set_boxed_authenticated_short_term_public_key(bastpk);
                        request
                    };

                    // Call remote channel auth.
                    future::Either::B(
                        Self::call::<api::ChannelAuthRequest, api::ChannelAuthResponse>(
                            shared_context.clone(),
                            api::METHOD_CHANNEL_AUTH,
                            request,
                        ).and_then(
                            move |_response: api::ChannelAuthResponse| {
                                let mut context = shared_context.lock().unwrap();

                                context.secure_channel.authentication_sent()
                            },
                        ),
                    )
                }),
            )
        });

        Box::new(result)
    }

    /// Close secure channel.
    ///
    /// If this method is not called, secure channel is automatically closed in
    /// a blocking fashion when the client is dropped.
    fn close_secure_channel(context: Arc<Mutex<Self>>) -> BoxFuture<()> {
        // Context moved into the closure (renamed for clarity).
        let shared_context = context;

        let result = future::lazy(move || -> BoxFuture<()> {
            {
                let context = shared_context.lock().unwrap();

                // If secure channel is not open we don't need to do anything.
                if context.secure_channel.is_closed() {
                    return Box::new(future::ok(()));
                }
            }

            // Send request to close channel.
            let request = api::ChannelCloseRequest::new();

            let result = Self::call::<api::ChannelCloseRequest, api::ChannelCloseResponse>(
                shared_context.clone(),
                api::METHOD_CHANNEL_CLOSE,
                request,
            ).and_then(move |_| {
                let mut context = shared_context.lock().unwrap();

                // Close local part of the secure channel.
                context.secure_channel.close();

                Ok(())
            });

            Box::new(result)
        });

        Box::new(result)
    }
}

/// Contract client.
pub struct RpcClient<Backend: RpcClientBackend + 'static> {
    /// Actual client context that can be shared between threads.
    context: Arc<Mutex<RpcClientContext<Backend>>>,
    /// Channel for processing requests.
    #[cfg(not(target_env = "sgx"))]
    request_tx: mpsc::UnboundedSender<Command>,
}

impl<Backend: RpcClientBackend + 'static> RpcClient<Backend> {
    /// Constructs a new contract client.
    ///
    /// The client API macro calls this.
    pub fn new(backend: Arc<Backend>, mr_enclave: MrEnclave, client_authentication: bool) -> Self {
        // Create request processing channel.
        #[cfg(not(target_env = "sgx"))]
        let (request_tx, request_rx) = mpsc::unbounded();

        let client = RpcClient {
            context: Arc::new(Mutex::new(RpcClientContext {
                backend: backend,
                mr_enclave: mr_enclave,
                secure_channel: SecureChannelContext::default(),
                client_authentication: client_authentication,
            })),
            #[cfg(not(target_env = "sgx"))]
            request_tx: request_tx,
        };

        #[cfg(not(target_env = "sgx"))]
        {
            // Spawn a task for processing requests.
            let request_processor =
                RpcClientContext::process_commands(client.context.clone(), request_rx);

            let context = client.context.lock().unwrap();
            context
                .backend
                .get_environment()
                .spawn(request_processor.discard());
        }

        client
    }

    /// Call a contract method.
    #[cfg(target_env = "sgx")]
    pub fn call<Rq, Rs>(&self, method: &str, request: Rq) -> BoxFuture<Rs>
    where
        Rq: Serialize,
        Rs: DeserializeOwned + Send + 'static,
    {
        RpcClientContext::call(self.context.clone(), &method, request)
    }

    /// Call a contract method.
    #[cfg(not(target_env = "sgx"))]
    pub fn call<Rq, Rs>(&self, method: &str, request: Rq) -> BoxFuture<Rs>
    where
        Rq: Serialize,
        Rs: DeserializeOwned + Send + 'static,
    {
        let (call_tx, call_rx) = oneshot::channel();

        // Create a request.
        let mut plain_request = api::PlainClientRequest::new();
        plain_request.set_method(method.to_owned());
        match serde_cbor::to_vec(&request) {
            Ok(payload) => plain_request.set_payload(payload),
            Err(_) => return Box::new(future::err(Error::new("payload serialize failed"))),
        }

        if let Err(_) = self.request_tx
            .unbounded_send(Command::Call(plain_request, call_tx))
        {
            return Box::new(future::err(Error::new("Command channel closed")));
        }

        // Wait for response.
        let result = call_rx
            .map_err(|_| Error::new("Command channel closed"))
            .and_then(|result| match result {
                Ok(plain_response) => Ok(serde_cbor::from_slice(&plain_response)?),
                Err(error) => Err(error),
            });

        Box::new(result)
    }

    /// Initialize a secure channel with the contract.
    ///
    /// If this method is not called, secure channel is automatically initialized
    /// when making the first request.
    #[cfg(target_env = "sgx")]
    pub fn init_secure_channel(&self) -> BoxFuture<()> {
        RpcClientContext::init_secure_channel(self.context.clone())
    }

    /// Initialize a secure channel with the contract.
    ///
    /// If this method is not called, secure channel is automatically initialized
    /// when making the first request.
    #[cfg(not(target_env = "sgx"))]
    pub fn init_secure_channel(&self) -> BoxFuture<()> {
        let (call_tx, call_rx) = oneshot::channel();

        if let Err(_) = self.request_tx
            .unbounded_send(Command::InitSecureChannel(call_tx))
        {
            return Box::new(future::err(Error::new("Command channel closed")));
        }

        // Wait for response.
        let result = call_rx
            .map_err(|_| Error::new("Command channel closed"))
            .and_then(|result| result);

        Box::new(result)
    }

    /// Close secure channel.
    ///
    /// If this method is not called, secure channel is automatically closed in
    /// a blocking fashion when the client is dropped.
    #[cfg(target_env = "sgx")]
    pub fn close_secure_channel(&self) -> BoxFuture<()> {
        RpcClientContext::close_secure_channel(self.context.clone())
    }

    /// Close secure channel.
    ///
    /// If this method is not called, secure channel is automatically closed in
    /// a blocking fashion when the client is dropped.
    #[cfg(not(target_env = "sgx"))]
    pub fn close_secure_channel(&self) -> BoxFuture<()> {
        let (call_tx, call_rx) = oneshot::channel();

        if let Err(_) = self.request_tx
            .unbounded_send(Command::CloseSecureChannel(call_tx))
        {
            return Box::new(future::err(Error::new("Command channel closed")));
        }

        // Wait for response.
        let result = call_rx
            .map_err(|_| Error::new("Command channel closed"))
            .and_then(|result| result);

        Box::new(result)
    }
}

impl<Backend: RpcClientBackend + 'static> Drop for RpcClient<Backend> {
    /// Close secure channel when going out of scope.
    fn drop(&mut self) {
        self.close_secure_channel().wait().unwrap_or(());
    }
}
