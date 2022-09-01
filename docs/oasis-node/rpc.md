# RPC

Oasis Node exposes an RPC interface to enable external applications to query
current [consensus] and [runtime] states, [submit transactions], etc.

The RPC interface is ONLY exposed via an AF_LOCAL socket called `internal.sock`
located in the node's data directory. **This interface should NEVER be directly
exposed over the network as it has no authentication and allows full control,
including shutdown, of a node.**

In order to support remote clients and different protocols (e.g. REST), a
gateway that handles things like authentication and rate limiting should be
used.

:::info

An example of such a gateway is the [Oasis Core Rosetta Gateway] which exposes
a subset of the consensus layer via the [Rosetta API].

:::

<!-- markdownlint-disable line-length -->
[consensus]: ../consensus/README.md
[runtime]: ../runtime/README.md
[submit transactions]: ../consensus/transactions.md#submission
[Oasis Core Rosetta Gateway]: https://github.com/oasisprotocol/oasis-core-rosetta-gateway
[Rosetta API]: https://www.rosetta-api.org
<!-- markdownlint-enable line-length -->

## Protocol

Like other parts of Oasis Core, the RPC interface exposed by Oasis Node uses the
[gRPC protocol] with the [CBOR codec (instead of Protocol Buffers)]. If your
application is written in Go, you can use the convenience gRPC wrappers provided
by Oasis Core to create clients. Check the [Oasis SDK] for more information.

For example to create a gRPC client connected to the Oasis Node endpoint exposed
by your local node at `/path/to/datadir/internal.sock` you can do:

```golang
import (
    // ...
    oasisGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
)

// ...

conn, err := oasisGrpc.Dial("unix:/path/to/datadir/internal.sock")
```

This will automatically handle setting up the required gRPC dial options for
setting up the CBOR codec and error mapping interceptors. For more detail about
the gRPC helpers see the [API documentation].

<!-- markdownlint-disable line-length -->
[gRPC protocol]: https://grpc.io
[CBOR codec (instead of Protocol Buffers)]: ../authenticated-grpc.md#cbor-codec
[API documentation]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/common/grpc?tab=doc
[Oasis SDK]: https://github.com/oasisprotocol/oasis-sdk
<!-- markdownlint-enable line-length -->

## Errors

We use a specific convention to provide more information about the exact error
that occurred when processing a gRPC request. See the [gRPC specifics] section
for details.

[gRPC specifics]: ../authenticated-grpc.md#errors

## Services

We use the same service method namespacing convention as gRPC over Protocol
Buffers. All Oasis Core services have unique identifiers starting with
`oasis-core.` followed by the service identifier. A single slash (`/`) is used
as the separator in method names, e.g., `/oasis-core.NodeControl/IsSynced`.

The following gRPC services are exposed (with links to API documentation):

* **General**
  * [Node Control] (`oasis-core.NodeController`)
* **Consensus Layer**
  * [Consensus (client subset)] (`oasis-core.Consensus`)
  * [Consensus (light client subset)] (`oasis-core.ConsensusLight`)
  * [Staking] (`oasis-core.Staking`)
  * [Registry] (`oasis-core.Registry`)
  * [Scheduler] (`oasis-core.Scheduler`)
  * [RootHash] (`oasis-core.RootHash`)
  * [Governance] (`oasis-core.Governance`)
  * [Beacon] (`oasis-core.Beacon`)
* **Runtime Layer**
  * [Storage] (`oasis-core.Storage`)
  * [Runtime Client] (`oasis-core.RuntimeClient`)

For more details about what the exposed services do see the respective
documentation sections. The Go API also provides gRPC client implementations for
all of the services which can be used after establishing a gRPC connection via
the internal socket (multiple clients can share the same gRPC connection). For
example in case of the consensus service using the connection we established in
the previous example:

```golang
import (
    // ...
    consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
)

// ...

cc := consensus.NewConsensusClient(conn)
err := cc.SubmitTx(ctx, &tx)
```

<!-- markdownlint-disable line-length -->
[Node Control]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/control/api?tab=doc#NodeController
[Consensus (client subset)]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/consensus/api?tab=doc#ClientBackend
[Consensus (light client subset)]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/consensus/api?tab=doc#LightClientBackend
[Staking]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#Backend
[Registry]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/registry/api?tab=doc#Backend
[Scheduler]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/scheduler/api?tab=doc#Backend
[RootHash]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/roothash/api?tab=doc#Backend
[Governance]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/governance/api?tab=doc#Backend
[Beacon]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/beacon/api?tab=doc#Backend
[Storage]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/storage/api?tab=doc#Backend
[Runtime Client]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/runtime/client/api?tab=doc#RuntimeClient
<!-- markdownlint-enable line-length -->
