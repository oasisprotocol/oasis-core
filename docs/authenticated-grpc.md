# Authenticated gRPC

Oasis Core nodes communicate between themselves over various protocols. One of
those protocols is [gRPC] which is currently used for the following:

* Compute nodes talking to storage nodes.
* Compute nodes talking to key manager nodes.
* Key manager nodes talking to other key manager nodes.
* Clients talking to compute nodes.
* Clients talking to key manager nodes.

All these communications can have access control policies attached specifying
who is allowed to perform certain actions at which point in time. This first
requires an authentication mechanism.

[gRPC]: https://grpc.io

## TLS

In order to authenticate both ends of a connection, gRPC is always used together
with TLS. However, since this is a decentralized network, there are some
specifics on how peer verification is performed when establishing a TLS session
between two nodes.

Instead of relying on Certificate Authorities, we use the [registry service]
provided by the [consensus layer]. Each node publishes its own trusted public
keys in the registry as part of its [signed node descriptor]. TLS sessions use
its own ephemeral [Ed25519 key pair] that is used to (self-)sign a node's X509
certificate. When verifying peer identities the public key on the certificate is
compared with the public key(s) published in the registry.

All TLS keys are ephemeral and nodes are encouraged to frequently rotate them
(the Oasis Core implementation in this repository supports this automatically).

For details on how certificate verification is performed see
[the `VerifyCertificate` implementation] in [`go/common/crypto/tls`].

<!-- markdownlint-disable line-length -->
[registry service]: consensus/services/registry.md
[consensus layer]: consensus/README.md
[signed node descriptor]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/common/node?tab=doc#Node
[Ed25519 key pair]: crypto.md
[the `VerifyCertificate` implementation]: https://github.com/oasisprotocol/oasis-core/tree/master/go/common/crypto/tls/verify.go
[`go/common/crypto/tls`]: https://github.com/oasisprotocol/oasis-core/tree/master/go/common/crypto/tls
<!-- markdownlint-enable line-length -->

## gRPC

Oasis Core uses some specific conventions that depart from the most common gRPC
setups and are described in the following sections.

### CBOR Codec

While gRPC is most commonly used with the Protocol Buffers codec the gRPC
protocol is agnostic to the actual underlying serialization format. Oasis Core
uses [CBOR] for encoding of all messages used in our gRPC services.

This requires that the codec is explicitly configured while setting up
connections. Our [gRPC helpers] automatically configure the correct codec so
using it should be transparent. The only quirk of this setup is that service
codegen is not available with arbitrary codecs, so glue code for both the server
and the client needs to be generated manually (for examples see the `grpc.go`
files in various `api` packages).

<!-- markdownlint-disable line-length -->
[CBOR]: encoding.md
[gRPC helpers]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/common/grpc?tab=doc
<!-- markdownlint-enable line-length -->

### Errors

As gRPC provides very limited error reporting capability in the form of a few
defined error codes, we extend this mechanism to support proper error remapping.

Detailed errors are returned as part of the [gRPC error details structure]. The
`Value` field of the first detail element contains the following CBOR-serialized
structure that specifies the (namespaced) error:

```golang
type grpcError struct {
    Module string `json:"module,omitempty"`
    Code   uint32 `json:"code,omitempty"`
}
```

If you use the provided [gRPC helpers] any errors will be mapped to registered
error types automatically.

<!-- markdownlint-disable line-length -->
[gRPC error details structure]: https://pkg.go.dev/google.golang.org/genproto/googleapis/rpc/status?tab=doc#Status
<!-- markdownlint-enable line-length -->

### Service Naming Convention

We use the same service method namespacing convention as gRPC over Protocol
Buffers. All Oasis Core services have unique identifiers starting with
`oasis-core.` followed by the service identifier. A single slash (`/`) is used
as the separator in method names, e.g., `/oasis-core.Storage/SyncGet`.
