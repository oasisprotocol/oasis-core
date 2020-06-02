# Runtime Host Protocol

The Runtime Host Protocol (RHP) is a simple RPC protocol which is used to
communicate between a runtime and an Oasis Core Node.

## Transport

The RHP assumes a reliable byte stream oriented transport underneath. The only
current implementation uses AF_LOCAL sockets and [Fortanix ABI streams] backed
by shared memory.

<!-- markdownlint-disable line-length -->
[Fortanix ABI streams]: https://edp.fortanix.com/docs/api/fortanix_sgx_abi/struct.Usercalls.html#streams
<!-- markdownlint-enable line-length -->

## Framing

All RHP messages use simple length-value framing with the value being encoded
using [canonical CBOR]. The frames are serialized on the wire as follows:

```
[4-byte message length (big endian)] [CBOR-serialized message]
```

Maximum allowed message size is 104857600 bytes.

[canonical CBOR]: ../encoding.md

## Messages

See the [API reference] for a list of all supported messages.

<!-- markdownlint-disable line-length -->
[API reference]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/worker/common/host/protocol?tab=doc#Body
<!-- markdownlint-enable line-length -->

## Operation

<!-- TODO: Describe RHP flows (initialization, RPC/batch dispatch, ...). -->

### Initialization

### Remote Attestation

### Transaction Batch Dispatch

### Local RPC and EnclaveRPC
