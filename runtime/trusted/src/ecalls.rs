//! ECALLs provided by the runtime interface.
use ekiden_enclave_trusted::utils::{read_enclave_request, write_enclave_response};
use ekiden_roothash_base::header::Header;
use ekiden_runtime_common::batch::CallBatch;

use super::dispatcher::{Dispatcher, RuntimeCallContext};

/// Invoke a runtime on a batch of calls and return the (encrypted) outputs.
#[no_mangle]
pub extern "C" fn runtime_call_batch(
    call_batch_data: *const u8,
    call_batch_length: usize,
    block_header_data: *const u8,
    block_header_length: usize,
    output_batch: *mut u8,
    output_batch_capacity: usize,
    output_batch_length: *mut usize,
) {
    // Parse call batch.
    let batch: CallBatch = read_enclave_request(call_batch_data, call_batch_length);
    let header: Header = read_enclave_request(block_header_data, block_header_length);

    // Build the runtime call context to be used for this batch.
    let ctx = RuntimeCallContext::new(header);

    // Dispatch all runtime invocations in the batch.
    let outputs = Dispatcher::get().dispatch_batch(batch, ctx);

    // Copy back output batch.
    write_enclave_response(
        &outputs,
        output_batch,
        output_batch_capacity,
        output_batch_length,
    );
}
