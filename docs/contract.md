# Contract

## Interfaces

### RPC interface

These methods must be invoked over a pre-established secure [RPC channel](rpc.md).

* `contract_submit(request: Signed<ContractCall>) -> call_id`
  Submit an async contract request. The request will be queued for execution and will be
  included in a future batch. The batch may be retrieved by the compute node via the
  `contract_get_batch` ECALL.
* `contract_reveal_outputs(proof_of_publication)`
  Reveal decryption key for previously returned encrypted outputs.

### Enclave edge interfaces

These are not high-fidelity method signatures.
For example, outputs may be pointer arguments instead of return values.

* ECALL `contract_take_batch() -> batch`
  Check if the enclave has a batch ready for execution and copy it over.
* ECALL `contract_call_batch(batch) -> outputs`
  Invoke a contract on a batch of calls and return the (encrypted) outputs.

## Examples

Note that the contract API is very similar to the [RPC API](rpc.md). The main difference is in the way how calls are executed, while RPCs are interactive the contract calls are asynchroneous as they need to be confirmed by consensus.

### Defining an API

An API may be defined by using the `contract_api` macro provided by `ekiden_core`. It is usually defined in its own API crate as it needs to be available for import both for enclaves and clients.

A simple API definition looks as follows:
```rust
use ekiden_core::contract::contract_api;

contract_api! {
    pub fn hello_world(u64) -> u64;
}

```

The contract API basically consists of a set of public contract method definitions, each starting with the keywords `pub fn`, similar to Rust functions.

A contract method definition looks similar to a Rust function definition and is composed from the following parts:
* Method name (e.g., `hello_world`) which defines how the method will be called.
* Request type (e.g., `u64`) which defines the Rust type containing the request message. This can be any type implementing Serde's `Deserialize` trait.
* Response type (e.g., `u64`) which defines the Rust type containing the response message. This can be any type implementing Serde's `Serialize` trait.

This same API definition can be used to generate both enclaves and clients. This is achieved by making the `contract_api` generate in its place another macro called `with_api` which can be used from both enclaves and clients.

## Creating an enclave contract implementation

In order to create an enclave contract implementation using the API we just defined, we need to import the API and instruct the contract system to generate some glue code that will call our method implementations.
This can be done as follows:
```rust
#![feature(use_extern_macros)]

use ekiden_trusted::contract::create_contract;
use dummy_api::with_api;

with_api! {
    create_contract!(api);
}
```

This creates the glue that is needed to connect the API definitions to our method implementations. Next, we need to define the methods themselves:
```rust
fn hello_world(request: &u64) -> Result<u64> {
    Ok(request + 42)
}
```

## Creating a client

To create a contract client for our API, we need to again import the API definitions and generate the required glue code:
```rust
#![feature(use_extern_macros)]

use ekiden_contract_client::create_contract_client;
use dummy_api::with_api;

with_api! {
    create_contract_client!(dummy, dummy_api, api);
}
```

This will create the client and necessary types inside a module named `dummy` (first argument to `create_contract_client` macro).
We can use this to create clients that talk to an Ekiden Compute node over gRPC:
```rust
use std::sync::Arc;

use ekiden_core::enclave::quote::MrEnclave;
use ekiden_core::signature::NullSignerVerifier;
use ekiden_rpc_client::backend::Web3RpcClientBackend;
use grpcio;

// TODO: Use actual signer.
let signer = Arc::new(NullSignerVerifier);

// Create gRPC event loop.
let grpc_environment = Arc::new(grpcio::EnvBuilder::new().build());

let client = dummy::Client::new(
    Arc::new(Web3RpcClientBackend::new(
        grpc_environment,
        "hostname",
        9001,
    ).unwrap()),
    MrEnclave([0; 32]),  // This needs to be an actual MRENCLAVE.
    signer,
);

let response = client.hello_world(&42).wait().unwrap();
assert_eq!(response, 84);
```
