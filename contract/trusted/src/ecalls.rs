//! ECALLs provided by the contract interface.
use ekiden_contract_common::batch::{CallBatch, OutputBatch};
use ekiden_enclave_trusted::utils::{read_enclave_request, write_enclave_response};

use super::batch::Batcher;
use super::dispatcher::Dispatcher;

/// Check if the enclave has a batch ready for execution and copy it over.
#[no_mangle]
pub extern "C" fn contract_take_batch(
    call_batch: *mut u8,
    call_batch_capacity: usize,
    call_batch_length: *mut usize,
) {
    let mut batcher = Batcher::get();
    let batch = batcher.take();

    // Copy back call batch.
    write_enclave_response(&batch, call_batch, call_batch_capacity, call_batch_length);
}

/// Invoke a contract on a batch of calls and return the (encrypted) outputs.
#[no_mangle]
pub extern "C" fn contract_call_batch(
    call_batch_data: *const u8,
    call_batch_length: usize,
    output_batch: *mut u8,
    output_batch_capacity: usize,
    output_batch_length: *mut usize,
) {
    // Parse call batch.
    let batch: CallBatch = read_enclave_request(call_batch_data, call_batch_length);

    // TODO: Actually decrypt batch.

    // Dispatch all contract invocations in the batch.
    let dispatcher = Dispatcher::get();
    let outputs = OutputBatch(batch.iter().map(|call| dispatcher.dispatch(call)).collect());

    // Copy back output batch.
    write_enclave_response(
        &outputs,
        output_batch,
        output_batch_capacity,
        output_batch_length,
    );
}
