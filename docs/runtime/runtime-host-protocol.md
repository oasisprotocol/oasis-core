# Runtime Host Protocol

The Runtime Host Protocol (RHP) is a simple RPC protocol which is used to
communicate between a runtime and an Oasis Core Compute Node.

## Transport

The RHP assumes a reliable byte stream oriented transport underneath. The only
current implementation uses AF_LOCAL sockets and [Fortanix ABI streams] backed
by shared memory to communicate with runtimes inside Intel SGX enclaves.

![Runtime Execution](../images/oasis-core-runtime-execution.svg)

<!-- markdownlint-disable line-length -->
[Fortanix ABI streams]: https://edp.fortanix.com/docs/api/fortanix_sgx_abi/struct.Usercalls.html#streams
<!-- markdownlint-enable line-length -->

## Framing

All RHP messages use simple length-value framing with the value being encoded
using [canonical CBOR]. The frames are serialized on the wire as follows:

```
[4-byte message length (big endian)] [CBOR-serialized message]
```

Maximum allowed message size is 16 MiB.

[canonical CBOR]: ../encoding.md

## Messages

Each [message] can be either a request or a response as specified by the type
field. Each request is assigned a unique 64-bit sequence number by the caller to
make it possible to correlate responses.

See the API reference ([Go], [Rust]) for a list of all supported message bodies.
In case the request resulted in an error, the special [`Error`] response body
must be used.

<!-- markdownlint-disable line-length -->
[message]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#Message
[Go]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#Body
[Rust]: https://github.com/oasisprotocol/oasis-core/tree/master/runtime/src/types.rs
[`Error`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#Error
<!-- markdownlint-enable line-length -->

## Operation

RHP allows two forms of communication:

* **Host-to-runtime** where the host (compute node) submits requests to the
  runtime to handle and the runtime provides responses. All such request
  [messages] are prefixed with `Runtime`.

* **Runtime-to-host** where the runtime submits requests to the host and the
  host provides responses. All such request [messages] are prefixed with
  `Host`.

In its lifetime, from connection establishment to its termination, the RHP
connection goes through the following states:

* *Uninitialized* is the default state of a newly created connection. In this
  state the connection could be used either on the runtime side or the host
  side. To proceed to the next state, the connection must be initialized either
  as a runtime or as a host. The [Rust implementation] only supports runtime
  mode while the [Go implementation] can be initialized in either mode by using
  either [`InitHost` or `InitGuest`].

* *Initializing* is the state when the connection is being initialized (see
  below for details). After a connection has been successfully initialized it
  will transition into *ready* state. If the initialization failed, it will
  instead transition into *closed* state.

* *Ready* is the state when the connection can be used to exchange messages in
  either direction.

* *Closed* is the state of the connection after it is considered closed. No
  messages may be exchanged at this point.

If either the runtime or the host generates an invalid message, either end may
terminate the connection (and/or the runtime process).

<!-- markdownlint-disable line-length -->
[messages]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#Body
[Rust implementation]: https://github.com/oasisprotocol/oasis-core/tree/master/runtime
[Go implementation]: https://github.com/oasisprotocol/oasis-core/tree/master/go/runtime/host/protocol
[`InitHost` or `InitGuest`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#Connection
<!-- markdownlint-enable line-length -->

### Initialization

Before a connection can be used, it must be initialized as either representing
the runtime end or the host (compute node) end. The [Rust implementation] only
supports being initialized as the runtime and the [Go implementation] is
currently only used as the host. If one uses the [`oasis-core-runtime` crate]
to build a runtime, initialization is handled automatically.

The initialization procedure is driven by the host and it proceeds as follows:

* The host sends [`RuntimeInfoRequest`] providing the runtime with its
  [designated identifier]. The identifier comes from the [registry service] in
  the consensus layer.

* The runtime must reply with a [`RuntimeInfoResponse`] specifying its own
  version and the version of the runtime host protocol that it supports. If the
  protocol version is incompatible, initialization fails.

After the initialization procedure, the connection can be used for other
messages. In case the runtime is running in a trusted execution environment
(TEE) like Intel SGX, the next required step is to perform remote attestation.

<!-- markdownlint-disable line-length -->
[`oasis-core-runtime` crate]: https://github.com/oasisprotocol/oasis-core/tree/master/runtime
[`RuntimeInfoRequest`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#RuntimeInfoRequest
[designated identifier]: identifiers.md
[registry service]: ../consensus/services/registry.md#runtimes
[`RuntimeInfoResponse`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#RuntimeInfoResponse
<!-- markdownlint-enable line-length -->

### Remote Attestation

When a runtime is executed in a TEE, it must perform remote attestation
immediately after initialization. The [Rust implementation] also requires that
remote attestation is periodically renewed and will start rejecting requests
otherwise. In case a runtime is not executed in a TEE, this step is skipped.

*NOTE: As currently Intel SGX is the only supported TEE, the elements of the
remote attestation protocol are in some parts very specific to Intel SGX. This
may change in the future when support for additional TEEs is added.*

Upon initialization the host performs the following steps:

* *[Intel SGX]* The host obtains information for the runtime to be able to
  generate an attestation report. This includes talking to the AESM service and
  the IAS configuration. The information includes the identity of the Quoting
  Enclave.

* The host sends [`RuntimeCapabilityTEERakInitRequest`] passing the information
  required for the runtime to initialize its own ephemeral Runtime Attestation
  Key (RAK). The RAK is valid for as long as the runtime is running.

The initialization then proceeds as follows, with the following steps also
being performed as part of periodic re-attestation:

* The host sends [`RuntimeCapabilityTEERakReportRequest`] requesting the runtime
  to generate an attestation report.

* The runtime prepares an attestation report based on the information provided
  during the first initialization step. It responds with
  [`RuntimeCapabilityTEERakReportResponse`] containing the public part of the
  RAK, the attestation report (binding RAK to the TEE identity) and a replay
  protection nonce.

* *[Intel SGX]* The host proceeds to submit the attestation report to the
  Quoting Enclave to receive a quote. It submits the received quote to the
  Intel Attestation Service (IAS) to receive a signed Attestation Verification
  Report (AVR). It submits the AVR to the runtime by sending a
  [`RuntimeCapabilityTEERakAvrRequest`].

* *[Intel SGX]* The runtime verifies the validity of the AVR, making sure that
  it is not a replay and that it in fact contains the correct enclave identity
  and the RAK binding.

* Upon successful verification the runtime is now ready to accept requests. As
  mentioned the attestation procedure must be performed periodically by the host
  as otherwise the runtime may start rejecting requests.

The compute node will submit remote attestation information to the consensus
[registry service] as part of its [node registration descriptor]. The registry
service will verify that the submitted AVR is in fact valid and corresponds to
the registered runtime enclave identity. It will reject node registrations
otherwise.

<!-- markdownlint-disable line-length -->
[`RuntimeCapabilityTEERakInitRequest`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#RuntimeCapabilityTEERakInitRequest
[`RuntimeCapabilityTEERakReportRequest`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#RuntimeCapabilityTEERakReportRequest
[`RuntimeCapabilityTEERakReportResponse`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#RuntimeCapabilityTEERakReportResponse
[`RuntimeCapabilityTEERakAvrRequest`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#RuntimeCapabilityTEERakAvrRequest
[node registration descriptor]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/common/node?tab=doc#Node
<!-- markdownlint-enable line-length -->

### Host-to-runtime

The following section describes the calls that a host can make to request
processing from the runtime after successfully performing initialization (and
initial remote attestation if running in a TEE).

#### Transaction Batch Dispatch

When a compute node needs to verify whether individual transactions are valid
it can optionally request the runtime to perform a simplified transaction check.
It can do this by sending a [`RuntimeCheckTxBatchRequest`] message. The runtime
should perform the required non-expensive checks, but should not fully execute
the transactions.

When a compute node receives a batch of transactions to process from the
transaction scheduler executor, it passes the batch to the runtime via the
[`RuntimeExecuteTxBatchRequest`] message. The runtime must execute the
transactions in the given batch and produce a set of state changes (storage
updates for the output and state roots). In case the runtime is running in a TEE
the execution results must be signed by the Runtime Attestation Key (see above).

<!-- markdownlint-disable line-length -->
[`RuntimeCheckTxBatchRequest`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#RuntimeCheckTxBatchRequest
[`RuntimeExecuteTxBatchRequest`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#RuntimeExecuteTxBatchRequest
<!-- markdownlint-enable line-length -->

#### EnclaveRPC

#### Key Manager Policy Update

#### Abort

The host can request the runtime to abort processing the current batch by
sending the [`RuntimeAbortRequest`] message. The request does not take any
arguments. In case the response does not indicate an error the abort is deemed
successful by the host.

In case the runtime does not reply quickly enough the host may terminate the
runtime and start a new instance.

<!-- markdownlint-disable line-length -->
[`RuntimeAbortRequest`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#RuntimeAbortRequest
<!-- markdownlint-enable line-length -->

#### Extensions

RHP provides a way for runtimes to support custom protocol extensions by
utilizing the [`RuntimeLocalRPCCallRequest`] and [`RuntimeLocalRPCCallResponse`]
messages.

<!-- markdownlint-disable line-length -->
[`RuntimeLocalRPCCallRequest`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#RuntimeLocalRPCCallRequest
[`RuntimeLocalRPCCallResponse`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#RuntimeLocalRPCCallResponse
<!-- markdownlint-enable line-length -->

### Runtime-to-host

The following section describes the calls that a runtime can make to request
processing from the host (or the wider distributed network on host's behalf).

#### EnclaveRPC to Remote Endpoints

#### Read-only Runtime Storage Access

The host exposes the [MKVS read syncer] interface (via the
[`HostStorageSyncRequest`] message) to enable runtimes read-only access to
global runtime storage.

<!-- markdownlint-disable line-length -->
[MKVS read syncer]: ../mkvs.md#read-syncer
[`HostStorageSyncRequest`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#HostStorageSyncRequest
<!-- markdownlint-enable line-length -->

#### Untrusted Local Storage Access

The host exposes a simple key-value local store that can be used by the runtime
to store arbitrary instance-specific data. **Note that if the runtime is running
in a TEE this store must be treated as UNTRUSTED as the host may perform
arbitrary attacks. The runtime should use TEE-specific sealing to ensure
integrity and confidentiality of any stored data.**

There are two local storage operations, namely get and set, exposed via
[`HostLocalStorageGetRequest`] and [`HostLocalStorageSetRequest`] messages,
respectively.

<!-- markdownlint-disable line-length -->
[`HostLocalStorageGetRequest`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#HostLocalStorageGetRequest
[`HostLocalStorageSetRequest`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/host/protocol?tab=doc#HostLocalStorageSetRequest
<!-- markdownlint-enable line-length -->
