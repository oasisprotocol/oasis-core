//! ECALLs provided by the contract interface.
use ekiden_contract_common::batch::CallBatch;
use ekiden_enclave_trusted::utils::{read_enclave_request, write_enclave_response};
use ekiden_roothash_base::header::Header;

use super::dispatcher::{ContractCallContext, Dispatcher};

/// Invoke a contract on a batch of calls and return the (encrypted) outputs.
#[no_mangle]
pub extern "C" fn contract_call_batch(
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

    // Build the contract call context to be used for this batch.
    let ctx = ContractCallContext::new(header);

    // Dispatch all contract invocations in the batch.
    let outputs = Dispatcher::get().dispatch_batch(batch, ctx);

    // Copy back output batch.
    write_enclave_response(
        &outputs,
        output_batch,
        output_batch_capacity,
        output_batch_length,
    );
}
