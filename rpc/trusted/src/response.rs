//! RPC response type.
use std;

use protobuf::Message;

use ekiden_rpc_common::api;

use super::request::Request;
use super::secure_channel::create_response_box;

/// Wrapper for responses.
pub struct Response {
    /// Response message.
    message: api::ClientResponse,
}

impl Response {
    /// Create new response.
    pub fn new<Rq>(request: &Request<Rq>, response: api::PlainClientResponse) -> Self {
        let mut message = api::ClientResponse::new();
        if let Some(ref public_key) = request.get_client_public_key() {
            // Encrypted response.
            match create_response_box(&public_key, &response) {
                Ok(response_box) => message.set_encrypted_response(response_box),
                _ => {
                    // Failed to create a cryptographic box for the response. This could
                    // be due to the session being incorrect or due to other issues. In
                    // this case, we should generate a plain error message.
                    message.set_plain_response(Self::generate_error(
                        api::PlainClientResponse_Code::ERROR_SECURE_CHANNEL,
                        "Failed to generate secure channel response",
                    ));
                }
            };
        } else {
            // Plain response.
            message.set_plain_response(response);
        }

        Response { message }
    }

    /// Create success response.
    pub fn success<Rq>(request: &Request<Rq>, payload: Vec<u8>) -> Self {
        // Prepare response.
        let mut response = api::PlainClientResponse::new();
        response.set_code(api::PlainClientResponse_Code::SUCCESS);
        response.set_payload(payload);

        Self::new(&request, response)
    }

    /// Create error response.
    pub fn error<Rq>(
        request: &Request<Rq>,
        error: api::PlainClientResponse_Code,
        message: &str,
    ) -> Self {
        Self::new(&request, Self::generate_error(error, &message))
    }

    /// Generate error response.
    fn generate_error(
        error: api::PlainClientResponse_Code,
        message: &str,
    ) -> api::PlainClientResponse {
        // Prepare response.
        let mut response = api::PlainClientResponse::new();
        response.set_code(error);

        let mut error = api::Error::new();
        error.set_message(message.to_string());

        let payload = error.write_to_bytes().expect("Failed to serialize error");
        response.set_payload(payload);

        response
    }

    /// Take response message.
    ///
    /// After calling this method, a default message will be left in its place.
    pub fn take_message(&mut self) -> api::ClientResponse {
        std::mem::replace(&mut self.message, api::ClientResponse::new())
    }
}
