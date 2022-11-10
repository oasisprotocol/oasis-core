# Consensus Layer

Oasis Core is designed around the principle of modularity. The _consensus layer_
is an interface that provides a number of important services to other parts of
Oasis Core. This allows, in theory, for the consensus backend to be changed. The
different backends live in [`go/consensus`], with the general interfaces in
[`go/consensus/api`]. The general rule is that anything outside of a specific
consensus backend package should be consensus backend agnostic.

For more details about the actual API that the consensus backends must provide
see the [consensus backend API documentation].

Currently the only supported consensus backend is [Tendermint], a BFT consensus
protocol. For this reason some API surfaces may not be fully consensus backend
agnostic.

Each consensus backend needs to provide the following services:

- [Epoch Time], an epoch-based time keeping service.
- [Random Beacon], a source of randomness for other services.
- [Staking], operations required to operate a PoS blockchain.
- [Registry], an entity/node/runtime public key and metadata registry service.
- [Committee Scheduler] service.
- [Governance] service.
- [Root Hash], runtime commitment processing and minimal runtime state keeping
  service.
- [Key Manager] policy state keeping service.

Each of the above services provides methods to query its current state. In order
to mutate the current state, each operation needs to be wrapped into a
[consensus transaction] and submitted to the consensus layer for processing.

Oasis Core defines an interface for each kind of service (in
`go/<service>/api`), with all concrete service implementations living together
with the consensus backend implementation. The service API defines the
transaction format for mutating state together with any query methods (both are
consensus backend agnostic).

<!-- markdownlint-disable line-length -->
[`go/consensus`]: https://github.com/oasisprotocol/oasis-core/tree/master/go/consensus
[`go/consensus/api`]: https://github.com/oasisprotocol/oasis-core/tree/master/go/consensus/api
[consensus backend API documentation]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/consensus/api?tab=doc
[Tendermint]: https://tendermint.com/
[Epoch Time]: services/epochtime.md
[Random Beacon]: services/beacon.md
[Staking]: services/staking.md
[Registry]: services/registry.md
[Committee Scheduler]: services/scheduler.md
[Governance]: services/governance.md
[Root Hash]: services/roothash.md
[Key Manager]: services/keymanager.md
[consensus transaction]: transactions.md
<!-- markdownlint-enable line-length -->

## Tendermint

![Tendermint](../images/oasis-core-consensus-tendermint.svg)

The Tendermint consensus backend lives in [`go/consensus/tendermint`].

For more information about Tendermint itself see
[the Tendermint Core developer documentation]. This section assumes familiarity
with the Tendermint Core concepts and APIs. When used as an Oasis Core consensus
backend, Tendermint Core is used as a library and thus lives in the same
process.

The Tendermint consensus backend is split into two major parts:

1. The first part is the **ABCI application** that represents the core logic
   that is replicated by Tendermint Core among the network nodes using the
   Tendermint BFT protocol for consensus.

1. The second part is the **query and transaction submission glue** that makes
   it easy to interact with the ABCI application, presenting everything via the
   Oasis Core Consensus interface.

<!-- markdownlint-disable line-length -->
[`go/consensus/tendermint`]: https://github.com/oasisprotocol/oasis-core/tree/master/go/consensus/tendermint
[the Tendermint Core developer documentation]: https://docs.tendermint.com/
<!-- markdownlint-enable line-length -->

### ABCI Application Multiplexer

Tendermint Core consumes consensus layer logic via the [ABCI protocol], which
assumes a single application. Since we have multiple services that need to be
provided by the consensus layer we use an _ABCI application multiplexer_ which
performs some common functions and dispatches transactions to the appropriate
service-specific handler.

The multiplexer lives in [`go/consensus/tendermint/abci/mux.go`] with the
multiplexed applications, generally corresponding to services required by the
_consensus layer_ interface living in [`go/consensus/tendermint/apps/<app>`].

<!-- markdownlint-disable line-length -->
[ABCI protocol]: https://github.com/tendermint/tendermint/blob/master/spec/abci/abci.md
[`go/consensus/tendermint/abci/mux.go`]: https://github.com/oasisprotocol/oasis-core/tree/master/go/consensus/tendermint/abci/mux.go
[`go/consensus/tendermint/apps/<app>`]: https://github.com/oasisprotocol/oasis-core/tree/master/go/consensus/tendermint/apps
<!-- markdownlint-enable line-length -->

### State Storage

All application state for the Tendermint consensus backend is stored using our
[Merklized Key-Value Store].

[Merklized Key-Value Store]: ../mkvs.md

### Service Implementations

Service implementations for the Tendermint consensus backend live in
[`go/consensus/tendermint/<service>`]. They provide the glue between the
services running as part of the ABCI application multiplexer and the Oasis Core
service APIs. The interfaces generally provide a read-only view of the consensus
layer state at a given height. Internally, these perform queries against the
ABCI application state.

#### Queries

Queries do not use the [ABCI query functionality] as that would incur needless
overhead for our use case (with Tendermint Core running in the same process).
Instead, each multiplexed service provides its own `QueryFactory` which can be
used to query state at a specific block height.

An example of a `QueryFactory` and the corresponding `Query` interfaces for the
staking service are as follows:

```golang
// QueryFactory is the staking query factory interface.
type QueryFactory interface {
    QueryAt(ctx context.Context, height int64) (Query, error)
}

// Query is the staking query interface.
type Query interface {
    TotalSupply(ctx context.Context) (*quantity.Quantity, error)
    CommonPool(ctx context.Context) (*quantity.Quantity, error)
    LastBlockFees(ctx context.Context) (*quantity.Quantity, error)

    // ... further query methods omitted ...
}
```

Implementations of this interface generally directly access the underlying ABCI
state storage to answer queries. Tendermint implementations of Oasis Core
consensus services generally follow the following pattern (example from the
staking service API for querying `TotalSupply`):

```golang
func (s *staking) TotalSupply(ctx context.Context, height int64) (*quantity.Quantity, error) {
    q, err := s.querier.QueryAt(ctx, height)
    if err != nil {
        return nil, err
    }

    return q.TotalSupply(ctx)
}
```

<!-- markdownlint-disable line-length -->
[`go/consensus/tendermint/<service>`]: https://github.com/oasisprotocol/oasis-core/tree/master/go/consensus/tendermint
[ABCI query functionality]: https://github.com/tendermint/tendermint/blob/master/spec/abci/abci.md#query-1
<!-- markdownlint-enable line-length -->

#### Transactions

Each [serialized signed Oasis Core transaction] directly corresponds to a
[Tendermint transaction]. Submission is performed by pushing the serialized
transaction bytes into the [mempool] where it first undergoes basic checks and
is then gossiped to the Tendermint P2P network.

Handling of basic checks and transaction execution is performed by the ABCI
application multiplexer mentioned above.

<!-- markdownlint-disable line-length -->
[serialized signed Oasis Core transaction]: transactions.md
[Tendermint transaction]: https://docs.tendermint.com/main/tendermint-core/using-tendermint.html#transactions
[mempool]: https://github.com/tendermint/tendermint/blob/master/spec/abci/abci.md#mempool-connection
<!-- markdownlint-enable line-length -->
