//! RPC method dispatcher.
use std::collections::HashMap;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutex as Mutex;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutexGuard as MutexGuard;
#[cfg(not(target_env = "sgx"))]
use std::sync::{Mutex, MutexGuard};

use serde::{de::DeserializeOwned, Serialize};
use serde_cbor;

use ekiden_common::{error::Result, profile_block};
use ekiden_enclave_common::utils::{read_enclave_request, write_enclave_response};
use ekiden_rpc_common::{api, reflection::ApiMethodDescriptor};

use super::{error::DispatchError, request, response, secure_channel::open_request_box};

/// List of methods that allow plain requests. All other requests must be done over
/// a secure channel.
const PLAIN_METHODS: &'static [&'static str] = &[
    api::METHOD_CHANNEL_INIT,
    // Authentication uses its own boxes very similar to RPC encryption, but with its own nonce
    // contexts.
    api::METHOD_CHANNEL_AUTH,
];

/// Handler for an API method.
pub trait ApiMethodHandler<Request, Response> {
    /// Invoke the method implementation and return a response.
    fn handle(&self, request: &request::Request<Request>) -> Result<Response>;
}

impl<Request, Response, F> ApiMethodHandler<Request, Response> for F
where
    Request: Send + 'static,
    Response: Send + 'static,
    F: Fn(&request::Request<Request>) -> Result<Response> + Send + Sync + 'static,
{
    fn handle(&self, request: &request::Request<Request>) -> Result<Response> {
        (*self)(request)
    }
}

/// Dispatcher for an API method.
pub trait ApiMethodHandlerDispatch {
    /// Dispatches the given raw request.
    fn dispatch(&self, request: &request::Request<Vec<u8>>) -> response::Response;
}

struct ApiMethodHandlerDispatchImpl<Request, Response> {
    descriptor: ApiMethodDescriptor,
    handler: Box<ApiMethodHandler<Request, Response> + Sync + Send>,
}

impl<'a, Request, Response> ApiMethodHandlerDispatch
    for ApiMethodHandlerDispatchImpl<Request, Response>
where
    Request: DeserializeOwned + Send + 'static,
    Response: Serialize + Send + 'static,
{
    /// Dispatches the given raw request.
    fn dispatch(&self, request: &request::Request<Vec<u8>>) -> response::Response {
        // If the method requires client attestation ensure that it has been provided.
        if self.descriptor.client_attestation_required && request.get_client_mr_enclave().is_none()
        {
            return response::Response::error(
                &request,
                api::PlainClientResponse_Code::ERROR_BAD_REQUEST,
                "Method requires client attestation",
            );
        }

        // Deserialize request.
        let request_message = match serde_cbor::from_slice(request) {
            Ok(message) => request.copy_metadata_to(message),
            _ => {
                return response::Response::error(
                    &request,
                    api::PlainClientResponse_Code::ERROR_BAD_REQUEST,
                    "Unable to parse request payload",
                );
            }
        };

        // Invoke handler.
        let response = match self.handler.handle(&request_message) {
            Ok(response) => response,
            Err(error) => {
                return response::Response::error(
                    &request,
                    api::PlainClientResponse_Code::ERROR,
                    error.message.as_str(),
                );
            }
        };

        // Serialize response.
        let response = match serde_cbor::to_vec(&response) {
            Ok(response) => response,
            _ => {
                return response::Response::error(
                    &request,
                    api::PlainClientResponse_Code::ERROR,
                    "Unable to serialize response payload",
                );
            }
        };

        response::Response::success(&request, response)
    }
}

/// Enclave method descriptor.
pub struct EnclaveMethod {
    /// Method name.
    name: String,
    dispatcher: Box<ApiMethodHandlerDispatch + Sync + Send>,
}

impl EnclaveMethod {
    /// Create a new enclave method descriptor.
    pub fn new<Request, Response, Handler>(method: ApiMethodDescriptor, handler: Handler) -> Self
    where
        Request: DeserializeOwned + Send + 'static,
        Response: Serialize + Send + 'static,
        Handler: ApiMethodHandler<Request, Response> + Sync + Send + 'static,
    {
        EnclaveMethod {
            name: method.name.clone(),
            dispatcher: Box::new(ApiMethodHandlerDispatchImpl {
                descriptor: method,
                handler: Box::new(handler),
            }),
        }
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn dispatch(&self, request: &request::Request<Vec<u8>>) -> response::Response {
        self.dispatcher.dispatch(&request)
    }
}

lazy_static! {
    // Global RPC dispatcher object.
    static ref DISPATCHER: Mutex<Dispatcher> = Mutex::new(Dispatcher::new());
}

/// RPC method dispatcher.
///
/// The dispatcher holds all registered RPC methods and provides an entry point
/// for their invocation.
pub struct Dispatcher {
    /// Registered RPC methods.
    methods: HashMap<String, EnclaveMethod>,
}

impl Dispatcher {
    /// Create a new RPC dispatcher instance.
    pub fn new() -> Self {
        let mut dispatcher = Dispatcher {
            methods: HashMap::new(),
        };

        // Register internal methods.
        dispatcher.add_method(EnclaveMethod::new(
            ApiMethodDescriptor {
                name: api::METHOD_CHANNEL_INIT.to_owned(),
                client_attestation_required: false,
            },
            |request: &request::Request<api::ChannelInitRequest>| {
                super::secure_channel::channel_init(request)
            },
        ));

        dispatcher.add_method(EnclaveMethod::new(
            ApiMethodDescriptor {
                name: api::METHOD_CHANNEL_AUTH.to_owned(),
                client_attestation_required: false,
            },
            |request: &request::Request<api::ChannelAuthRequest>| {
                super::secure_channel::channel_auth(request)
            },
        ));

        dispatcher
    }

    /// Global dispatcher instance.
    ///
    /// Calling this method will take a lock on the global instance which
    /// will be released once the value goes out of scope.
    pub fn get<'a>() -> MutexGuard<'a, Self> {
        DISPATCHER.lock().unwrap()
    }

    /// Register a new method in the dispatcher.
    pub fn add_method(&mut self, method: EnclaveMethod) {
        self.methods.insert(method.get_name().clone(), method);
    }

    /// Dispatches a raw RPC request.
    pub fn dispatch(&self, request: request::Request<Vec<u8>>) -> response::Response {
        // If an error occurred during request processing, forward it.
        if let Some(ref error) = request.get_error() {
            return response::Response::error(&request, error.code, &error.message);
        }

        // Get request method.
        let method = request
            .get_method()
            .expect("Non-errored request without method passed to dispatcher");

        match self.methods.get(method) {
            Some(method_dispatch) => method_dispatch.dispatch(&request),
            None => response::Response::error(
                &request,
                api::PlainClientResponse_Code::ERROR_METHOD_NOT_FOUND,
                "Method not found",
            ),
        }
    }
}

/// RPC dispatch ECALL entry point.
///
/// This method gets executed every time there are some requests are to
/// be dispatched into this enclave.
#[no_mangle]
pub extern "C" fn rpc_call(
    request_data: *const u8,
    request_length: usize,
    response_data: *mut u8,
    response_capacity: usize,
    response_length: *mut usize,
) {
    // Parse requests.
    let requests = {
        profile_block!("parse_request");

        let mut enclave_request: api::EnclaveRequest =
            read_enclave_request(request_data, request_length);
        let client_requests = enclave_request.take_client_request();
        let mut requests = vec![];

        for mut client_request in client_requests.into_iter() {
            if client_request.has_encrypted_request() {
                // Encrypted request.
                let plain_request = match open_request_box(&client_request.get_encrypted_request())
                {
                    Ok(plain_request) => plain_request,
                    _ => request::Request::error(DispatchError::new(
                        api::PlainClientResponse_Code::ERROR_SECURE_CHANNEL,
                        "Unable to open secure channel request",
                    )),
                };

                requests.push(plain_request);
            } else {
                // Plain request.
                let mut plain_request = client_request.take_plain_request();
                let plain_request = match PLAIN_METHODS
                    .iter()
                    .find(|&method| method == &plain_request.get_method())
                {
                    Some(_) => request::Request::new(
                        plain_request.take_payload(),
                        plain_request.take_method(),
                        None,
                        None,
                    ),
                    None => {
                        // Method requires a secure channel.
                        request::Request::error(DispatchError::new(
                            api::PlainClientResponse_Code::ERROR_METHOD_SECURE,
                            "Method call must be made over a secure channel",
                        ))
                    }
                };

                requests.push(plain_request);
            }
        }

        requests
    };

    // Process requests.
    let responses = {
        profile_block!("process_requests");

        let dispatcher = Dispatcher::get();
        let mut responses = vec![];
        for request in requests {
            responses.push(dispatcher.dispatch(request));
        }

        responses
    };

    // Generate response.
    {
        profile_block!("return_response");

        // Add all responses.
        let mut enclave_response = api::EnclaveResponse::new();
        {
            let client_responses = enclave_response.mut_client_response();
            for mut response in responses {
                client_responses.push(response.take_message());
            }
        }

        // Copy back response.
        write_enclave_response(
            &enclave_response,
            response_data,
            response_capacity,
            response_length,
        );
    }
}
