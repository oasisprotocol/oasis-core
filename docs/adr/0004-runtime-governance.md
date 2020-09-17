# ADR 0004: Runtime Governance

## Changelog

- 2020-10-07: Add per-role max node limits, minimum required election pool size
- 2020-09-30: Add entity whitelist admission policy max nodes limit
- 2020-09-17: Initial draft

## Status

Accepted

## Context

Currently all runtimes can only be governed by a single entity -- the runtime
owner. In this regard governance means being able to update certain fields in
the runtime descriptor stored by the consensus layer registry service. On one
hand the runtime descriptor contains security-critical parameters and on the
other there needs to be a mechanism through which the runtimes can be upgraded
(especially so for TEE-based runtimes where a specific runtime binary is
enforced via remote attestation mechanisms).

This proposal extends runtime governance options and enables a path towards
runtimes that can define their own governance mechanisms. This proposal assumes
that [ADR 0003] has been adopted and runtimes can have their own accounts in the
staking module.

## Decision

This proposal takes a simplistic but powerful approach which allows each runtime
to choose its governance model upon its first registration. It does so through
a newly introduced field in the runtime descriptor which indicates how the
runtime descriptor can be updated in the future.

### Runtime Descriptor

The runtime descriptor version is bumped to `2`. Version `1` descriptors are
accepted at genesis and are converted to the new format by assuming the entity
governance model as that is the only option in v1. All new runtime registrations
must use the v2 descriptor.

#### Governance Model

This proposal updates the runtime descriptor by adding fields as follows:

```golang
type Runtime struct {
    // GovernanceModel specifies the runtime governance model.
    GovernanceModel RuntimeGovernanceModel `json:"governance_model"`

    // ... existing fields omitted ...
}

// RuntimeGovernanceModel specifies the runtime governance model.
type RuntimeGovernanceModel uint8

const (
    GovernanceEntity    RuntimeGovernanceModel = 1
    GovernanceRuntime   RuntimeGovernanceModel = 2
    GovernanceConsensus RuntimeGovernanceModel = 3
)

// ... some text serialization methods omitted ...
```

The `governance_model` field can specifiy one of the following governance
models:

- **Entity governance (`GovernanceEntity`).** This causes the runtime to behave
  exactly as before, the runtime owner (indicated by `entity_id` in the runtime
  descriptor) is the only one who can update the runtime descriptor via
  `registry.RegisterRuntime` method calls.

  The runtime owner is also the one that needs to provide the required stake
  in escrow in order to avoid the runtime from being suspended. As before note
  that anyone can delegate the required stake to the runtime owner in order to
  enable runtime operation (but the owner can always prevent the runtime from
  operating by performing actions which would cause the stake claims to no
  longer be satisfied).

- **Runtime-defined governance (`GovernanceRuntime`).** In this case the runtime
  itself is the only one who can update the runtime descriptor by emitting a
  runtime message. The runtime owner (indicated by `entity_id`) is not able to
  perform any updates after the initial registration and such attempts must
  return `ErrForbidden`.

  The runtime itself is the one that needs to provide the required stake in
  escrow in order to avoid the runtime from being suspended. This assumes that
  runtimes can have accounts in the staking module as specified by [ADR 0003].
  Note that anyone can delegate the required stake to a runtime in order to
  enable its operation.

- **Consensus layer governance (`GovernanceConsensus`).** In this case only the
  consensus layer itself can update the runtime descriptor either through a
  network upgrade or via a consensus layer governance mechanism not specified by
  this proposal.

  Runtimes using this governance model are never suspended and do not need to
  provide stake in escrow.

  Runtimes using this governance model cannot be registered/updated via regular
  registry method calls or runtime messages (doing so must return
  `ErrForbidden`). Instead such a runtime can only be registered at genesis,
  through a network upgrade or via a consensus layer governance mechanism not
  specified by this proposal.

#### Entity Whitelist Admission Policy

The entity whitelist admission policy configuration structure is changed to
allow specifying the maximum number of nodes that each entity can register under
the given runtime for each role.

```golang
type EntityWhitelistConfig struct {
    // MaxNodes is the maximum number of nodes that an entity can register under
    // the given runtime for a specific role. If the map is empty or absent, the
    // number of nodes is unlimited. If the map is present and non-empty, the
    // the number of nodes is restricted to the specified maximum (where zero
    // means no nodes allowed), any missing roles imply zero nodes.
    MaxNodes map[node.RolesMask]uint16 `json:"max_nodes,omitempty"`
}

type EntityWhitelistRuntimeAdmissionPolicy struct {
    Entities map[signature.PublicKey]EntityWhitelistConfig `json:"entities"`
}
```

The new `max_nodes` field specifies the maximum number of nodes an entity can
register for the given runtime for each role. If the map is empty or absent, the
number of nodes is unlimited. If the map is present and non-empty, the number of
nodes is restricted to the specified number (where zero means no nodes are
allowed). Any missing roles imply zero nodes.

Each key (roles mask) in the `max_nodes` map must specify a single role,
otherwise the runtime descriptor is rejected with `ErrInvalidArgument`.

When transforming runtime descriptors from version 1, an entry in the `entities`
field maps to an `EntityWhitelistConfig` structure with `max_nodes` absent,
denoting that an unlimited number of nodes is allowed (as before).

#### Minimum Required Committee Election Pool Size

The executor and storage runtime parameters are updated to add a new field
defining the minimum required committee election pool size. The committee
scheduler is updated to refuse election for a given runtime committee in case
the number of candidate nodes is less than the configured minimum pool size.

```golang
type ExecutorParameters struct {
    // MinPoolSize is the minimum required candidate compute node pool size.
    MinPoolSize uint64 `json:"min_pool_size"`

    // ... existing fields omitted ...
}

type StorageParameters struct {
    // MinPoolSize is the minimum required candidate storage node pool size.
    MinPoolSize uint64 `json:"min_pool_size"`

    // ... existing fields omitted ...
}
```

The value of `min_pool_size` must be non-zero and must be equal to or greater
than the corresponding sum of `group_size` and `group_backup_size`. Otherwise
the runtime descriptor is rejected with `ErrInvalidArgument`.

When transforming runtime descriptors from version 1, `min_pool_size` for the
executor committee is computed as `group_size + group_backup_size` while the
`min_pool_size` for the storage committee is equal to `group_size`.

### State

This proposal introduces/updates the following consensus state in the registry
module:

#### Stored Runtime Descriptors

Since the runtime descriptors can now be updated by actors other than the
initial registering entity, it does not make sense to store signed runtime
descriptors. The value of storage key prefixed with `0x13` which previously
contained signed runtime descriptors is modified to store plain runtime
descriptors.

### Genesis Document

This proposal updates the registry part of the genesis document as follows:

- The type of the `runtimes` field is changed to a list of runtime descriptors
  (was a list of _signed_ runtime descriptors before).

- The type of the `suspended_runtimes` field is changed to a list of runtime
  descriptors (was a list of _signed_ runtime descriptors before).

Runtime descriptors must be transformed to support the new fields.

### Transaction Methods

This proposal updates the following transaction methods in the registry module:

#### Register Runtime

Runtime registration enables a new runtime to be created or an existing runtime
to be updated (in case the governance model allows it).

**Method name:**

```
registry.RegisterRuntime
```

The body of a register runtime transaction must be a `Runtime` descriptor.
The signer of the transaction must be the owning entity key.

Registering a runtime may require sufficient stake in either the owning entity's
(when entity governance is used) or the runtime's (when runtime governance is
used) escrow account.

Changing the governance model from `GovernanceEntity` to `GovernanceRuntime` is
allowed. Any other governance model changes are not allowed and must fail with
`ErrForbidden`. Support for other changes is deferred to a consensus layer
governance mechanism not specified by this proposal.

Using the `GovernanceRuntime` governance model for a runtime of any kind other
than `KindCompute` must return `ErrInvalidArgument`.

### Messages

This proposal introduces the following runtime messages:

#### Update Runtime Descriptor

The update runtime descriptor message enables a runtime to update its own
descriptor when the current governance model allows it.

**Field name:**

```
update_runtime
```

**Body:**

```golang
type UpdateRuntimeMessage struct {
    registry.Runtime
}
```

The body of the update runtime descriptor message is a new runtime descriptor
that must be for the runtime emitting this message. Otherwise the message is
considered malformed.

The actions performed when processing the message are the same as those
performed when processing the `registry.RegisterRuntime` method call, just made
on the runtime's (instead of an entity's) behalf.

### Consensus Parameters

#### Registry

This proposal introduces the following new consensus parameters in the registry
module:

- `enable_runtime_governance_models` (set of `RuntimeGovernanceModel`) specifies
  the set of runtime governance models that are allowed to be used when
  creating/updating registrations (either via method calls or via runtime
  messages). In case a runtime is using a governance model not specified in this
  list, an update to such a runtime must fail with `ErrForbidden`.

### Rust Runtime Support Library

The Rust runtime support library (`oasis-core-runtime`) must be updated to
support the updated and newly needed message structures (the runtime descriptor
and the update runtime message).

## Consequences

### Positive

- Runtimes can define their governance model, enabling them to become more
  decentralized while still allowing upgrades.

- Runtimes using the entity whitelist admission policy can limit the number of
  nodes that each entity can register.

- Runtimes can specify the minimum size of the compute/storage node pool from
  which committees are elected.

### Negative

### Neutral

## References

- [ADR 0003] - Consensus/Runtime Token Transfer

[ADR 0003]: 0003-consensus-runtime-token-transfer.md
