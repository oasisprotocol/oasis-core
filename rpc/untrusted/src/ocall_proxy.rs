use sgx_types::*;

use std;
use std::ptr;

use ekiden_rpc_common::client::ClientEndpoint;

use super::router::RpcRouter;

/// Proxy for sgx_init_quote.
#[no_mangle]
pub extern "C" fn untrusted_init_quote(
    p_target_info: *mut sgx_target_info_t,
    p_gid: *mut sgx_epid_group_id_t,
) -> sgx_status_t {
    unsafe { sgx_init_quote(p_target_info, p_gid) }
}

/// Proxy for sgx_get_quote.
#[no_mangle]
pub extern "C" fn untrusted_get_quote(
    p_report: *const sgx_report_t,
    quote_type: sgx_quote_sign_type_t,
    p_spid: *const sgx_spid_t,
    p_quote: *mut u8,
    _quote_capacity: u32,
    quote_size: *mut u32,
) -> sgx_status_t {
    // Calculate quote size.
    let status = unsafe { sgx_calc_quote_size(ptr::null(), 0, quote_size) };

    match status {
        sgx_status_t::SGX_SUCCESS => {}
        _ => return status,
    };

    // Get quote from the quoting enclave.
    unsafe {
        sgx_get_quote(
            p_report,
            quote_type,
            p_spid,
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            p_quote as *mut sgx_quote_t,
            *quote_size,
        )
    }
}

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
