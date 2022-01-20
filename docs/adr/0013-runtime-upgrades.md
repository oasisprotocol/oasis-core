# ADR 0013: Runtime Upgrade Improvements

## Changelog

- {date}: {changelog}

## Status

Proposed

## Context

Currently major runtime updates incur at least one epoch worth of downtime
for the transition period.  This is suboptimal, and can be improved to allow
seamless runtime updates, with some changes to the runtime descriptor and
scheduler behavior.

## Decision

Implement support for seamless breaking runtime upgrades.

## Implementation

Runtime descriptor related changes:

```golang
// Runtime represents a runtime.
type Runtime struct { // nolint: maligned
	cbor.Versioned

	// ID is a globally unique long term identifier of the runtime.
	ID common.Namespace `json:"id"`

	// EntityID is the public key identifying the Entity controlling
	// the runtime.
	EntityID signature.PublicKey `json:"entity_id"`

	// Genesis is the runtime genesis information.
	Genesis RuntimeGenesis `json:"genesis"`

	// Kind is the type of runtime.
	Kind RuntimeKind `json:"kind"`

	// TEEHardware specifies the runtime's TEE hardware requirements.
	TEEHardware node.TEEHardware `json:"tee_hardware"`

	// KeyManager is the key manager runtime ID for this runtime.
	KeyManager *common.Namespace `json:"key_manager,omitempty"`

	// Executor stores parameters of the executor committee.
	Executor ExecutorParameters `json:"executor,omitempty"`

	// TxnScheduler stores transaction scheduling parameters of the executor
	// committee.
	TxnScheduler TxnSchedulerParameters `json:"txn_scheduler,omitempty"`

	// Storage stores parameters of the storage committee.
	Storage StorageParameters `json:"storage,omitempty"`

	// AdmissionPolicy sets which nodes are allowed to register for this runtime.
	// This policy applies to all roles.
	AdmissionPolicy RuntimeAdmissionPolicy `json:"admission_policy"`

	// Constraints are the node scheduling constraints.
	Constraints map[scheduler.CommitteeKind]map[scheduler.Role]SchedulingConstraints `json:"constraints,omitempty"`

	// Staking stores the runtime's staking-related parameters.
	Staking RuntimeStakingParameters `json:"staking,omitempty"`

	// GovernanceModel specifies the runtime governance model.
	GovernanceModel RuntimeGovernanceModel `json:"governance_model"`

	// Deployments specifies the runtime deployments (versions).
	Deployments []*VersionInfo `json:"deployments"`
}

// VersionInfo is the per-runtime version information.
type VersionInfo struct {
	// Version of the runtime.
	Version version.Version `json:"version"`

	// ValidFrom stores the epoch at which, this version is valid.
	ValidFrom beacon.EpochTime `json:"valid_from"`

	// TEE is the enclave version information, in an enclave provider specific
	// format if any.
	TEE []byte `json:"tee,omitempty"`

	// TODO: Figure out if there should be a digest of the enclave binary
	// to catch misconfigurations.  It is the author's opinion that such
	// a thing should exist, and that it is compatible with people's desires
	// to build their own runtime binaries, and any mismatches are a failure
	// of our build process to be deterministic, a documetnation failure,
	// or user error.
}
```

The intended workflow here is to:

- Deploy runtimes with the initial Deployment populated.

- Update the runtime version via the deployment of a new version
  of the descriptor with an additional version info entry.  Nodes
  must upgrade their runtime binary and configuration by the
  `ValidFrom` epoch or the runtime will halt.

- Aborting or altering pending updates via the deployment of a new version
  of the descriptor with the removed/ammended not-yet-valid `Deployments`
  is possible in this design, but perhaps should be forbidden.

- Altering exisiting `Deployments` entries is strictly forbidden.

The existing node descriptor is a flat vector of `Runtime` entries
containing the runtime ID, version, and TEE information, so no changes
are required.

The only scheduler and worker side changes are to incorporate the runtime
version into scheduling, and to pick the correct deployed version of the
runtime to use, both on a once-per-epoch-per-runtime basis.

## Consequences


### Positive

- Seamless runtime upgrades will be possible.

- The code changes required are relatively minimal, and this is likely
  the simplest possible solution that will work.

### Negative

- It may be overly simplistic.
