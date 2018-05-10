use std;

use ekiden_rpc_common::client::ClientEndpoint;

use super::router::RpcRouter;

/// Interface for outgoing RPC calls (to other enclaves or services).
#[no_mangle]
pub extern "C" fn untrusted_rpc_call(
    endpoint: u16,
    request_data: *const u8,
    request_length: usize,
    response_data: *mut u8,
    response_capacity: usize,
    response_length: *mut usize,
) {
    // Convert raw request to Rust datatypes.
    let request = unsafe { std::slice::from_raw_parts(request_data, request_length) };

    // Invoke dispatcher.
    let response = match ClientEndpoint::from_u16(endpoint) {
        Some(endpoint) => RpcRouter::get().dispatch(&endpoint, request.to_vec()),
        None => {
            // Bad endpoint.
            // TODO: Handle errors?
            vec![]
        }
    };

    // Convert response back to raw bytes.
    if response.len() <= response_capacity {
        unsafe {
            for i in 0..response.len() as isize {
                std::ptr::write(response_data.offset(i), response[i as usize]);
            }

            *response_length = response.len();
        };
    }
}
