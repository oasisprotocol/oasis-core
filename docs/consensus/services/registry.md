# Registry

The registry service is responsible for managing a registry of runtime, entity
and node public keys and metadata.

The service interface definition lives in [`go/registry/api`]. It defines the
supported queries and transactions. For more information you can also check out
the [consensus service API documentation].

<!-- markdownlint-disable line-length -->
[`go/registry/api`]: https://github.com/oasisprotocol/oasis-core/tree/master/go/registry/api
[consensus service API documentation]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/registry/api?tab=doc
<!-- markdownlint-enable line-length -->

## Resources

The registry service manages different kinds of resources which are described
from a high level perspective in this section.

### Entities and Nodes

An entity managed by the registry service is a key pair that owns resources in
the registry. It can represent an organization or an individual with [stake] on
the network.

Currently, an entity can own the following types of resources:

* nodes and
* runtimes.

A node is a device (process running in a VM, on bare metal, in a container,
etc.) that is participating in a committee on the Oasis Core network. It is
identified by its own key pair.

The reason for separating entities from nodes is to enable separation of
concerns. Both nodes and entities require stake to operate (e.g., to be
registered in the registry and be eligible for specific roles). While entities
have their own (or [delegated]) stake, nodes use stake provided by entities that
operate them. Nodes need to periodically refresh their resource descriptor in
the registry in order for it to remain fresh and to do this they need to have
online access to their corresponding private key(s).

On the other hand entities' private keys are more sensitive as they can be used
to manage stake and other resources. For this reason they should usually be kept
offline and having entities as separate resources enables that.

[stake]: staking.md
[delegated]: staking.md#delegation

### Runtimes

A [runtime] is effectively a replicated application with shared state. The
registry resource describes a runtime's operational parameters, including its
identifier, kind, admission policy, committee scheduling, storage, governance
model, etc. For a full description of the runtime descriptor see
[the `Runtime` structure].

<!-- markdownlint-disable no-space-in-emphasis -->
The chosen governance model indicates how the runtime descriptor can be updated
in the future.

There are currently three supported governance models:

* **Entity governance** where the runtime owner is the only one who can update
  the runtime descriptor via `registry.RegisterRuntime` method calls.

* **Runtime-defined governance** where the runtime itself is the only one who
  can update the runtime descriptor by emitting a runtime message.

* **Consensus layer governance** where only the consensus layer itself can
  update the runtime descriptor through network governance.
<!-- markdownlint-enable no-space-in-emphasis -->

<!-- markdownlint-disable line-length -->
[runtime]: ../../runtime/README.md
[the `Runtime` structure]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/registry/api?tab=doc#Runtime
<!-- markdownlint-enable line-length -->

## Methods

The following sections describe the methods supported by the consensus registry
service.

### Register Entity

Entity registration enables a new entity to be created. A new register entity
transaction can be generated using [`NewRegisterEntityTx`].

**Method name:**

```
registry.RegisterEntity
```

The body of a register entity transaction must be a [`SignedEntity`] structure,
which is a [signed envelope] containing an [`Entity`] descriptor. The signer of
the entity MUST be the same as the signer of the transaction.

Registering an entity may require sufficient stake in the entity's
[escrow account].

<!-- markdownlint-disable line-length -->
[`NewRegisterEntityTx`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/registry/api?tab=doc#NewRegisterEntityTx
[`SignedEntity`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/common/entity?tab=doc#SignedEntity
[`Entity`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/common/entity?tab=doc#Entity
[signed envelope]: ../../crypto.md#signed-envelope
[escrow account]: staking.md#escrow
<!-- markdownlint-enable line-length -->

### Deregister Entity

Entity deregistration enables an existing entity to be removed. A new deregister
entity transaction can be generated using [`NewDeregisterEntityTx`].

**Method name:**

```
registry.DeregisterEntity
```

The body of a register entity transaction must be `nil`. The entity is implied
to be the signer of the transaction.

_If an entity still has either nodes or runtimes registered, it is not possible
to deregister an entity and such a transaction will fail._

<!-- markdownlint-disable line-length -->
[`NewDeregisterEntityTx`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/registry/api?tab=doc#NewDeregisterEntityTx
<!-- markdownlint-enable line-length -->

### Register Node

Node registration enables a new node to be created. A new register node
transaction can be generated using [`NewRegisterNodeTx`].

**Method name:**

```
registry.RegisterNode
```

The body of a register entity transaction must be a [`MultiSignedNode`]
structure, which is a [multi-signed envelope] containing a [`Node`] descriptor.
The signer of the transaction MUST be the node identity key.

The owning entity MUST have the given node identity public key whitelisted in
the `Nodes` field in its [`Entity`] descriptor.

The node descriptor structure MUST be signed by all of the following keys:

* Node identity key.
* Consensus key.
* TLS key.
* P2P key.

Registering a node may require sufficient stake in the owning entity's
[escrow account]. There are two kinds of thresholds that the node may need to
satisfy:

* Global thresholds are the same for all runtimes and are defined by the
  consensus parameters (see [`Thresholds` in staking consensus parameters]).

* In _addition_ to the global thresholds, each runtime the node is registering
  for may define their own thresholds. The runtime-specific thresholds are
  defined in the [`Staking` field] in the runtime descriptor.

In case the node is registering for multiple runtimes, it needs to satisfy the
sum of thresholds of all the runtimes it is registering for.

<!-- markdownlint-disable line-length -->
[`NewRegisterNodeTx`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/registry/api?tab=doc#NewRegisterNodeTx
[`MultiSignedNode`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/common/node?tab=doc#MultiSignedNode
[`Node`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/common/node?tab=doc#Node
[multi-signed envelope]: ../../crypto.md#multi-signed-envelope
[`Thresholds` in staking consensus parameters]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#ConsensusParameters.Thresholds
[`Staking` field]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/registry/api?tab=doc#Runtime.Staking
<!-- markdownlint-enable line-length -->

### Unfreeze Node

Node unfreezing enables a previously frozen (e.g., due to slashing) node to be
thawed so it can again be eligible for committee elections. A new unfreeze node
transaction can be generated using [`NewUnfreezeNodeTx`].

**Method name:**

```
registry.UnfreezeNode
```

**Body:**

```golang
type UnfreezeNode struct {
    NodeID signature.PublicKey `json:"node_id"`
}
```

**Fields:**

* `node_id` specifies the node identifier of the node to thaw.

The transaction signer MUST be the entity key that owns the node.

Thawing a node requires that the node's freeze period has already passed. The
freeze period for any given attributable fault (e.g., double signing) is a
consensus parameter (see [`Slashing` in staking consensus parameters]).

<!-- markdownlint-disable line-length -->
[`NewUnfreezeNodeTx`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/registry/api?tab=doc#NewUnfreezeNodeTx
[`Slashing` in staking consensus parameters]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/staking/api?tab=doc#ConsensusParameters.Slashing
<!-- markdownlint-enable line-length -->

### Register Runtime

Runtime registration enables a new runtime to be created. A new register
runtime transaction can be generated using [`NewRegisterRuntimeTx`].

**Method name:**

```
registry.RegisterRuntime
```

The body of a register runtime transaction must be a [`Runtime`] descriptor.
The signer of the transaction MUST be the owning entity key.

Registering a runtime may require sufficient stake in either the owning
entity's (when entity governance is used) or the runtime's (when runtime
governance is used) [escrow account].

Changing the governance model from entity governance to runtime governance is
allowed. Any other governance model changes are not allowed.

<!-- markdownlint-disable line-length -->
[`NewRegisterRuntimeTx`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/registry/api?tab=doc#NewRegisterRuntimeTx
[`Runtime`]: https://pkg.go.dev/github.com/oasisprotocol/oasis-core/go/registry/api?tab=doc#Runtime
<!-- markdownlint-enable line-length -->

## Events

## Test Vectors

To generate test vectors for various registry [transactions], run:

```bash
make -C go registry/gen_vectors
```

For more information about the structure of the test vectors see the section
on [Transaction Test Vectors].

[transactions]: ../transactions.md
[Transaction Test Vectors]: ../test-vectors.md
