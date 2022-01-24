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
	// Deployments specifies the runtime deployments (versions).
	Deployments []*VersionInfo `json:"deployments"`

	// Version field isrelocated to inside the VersionInfo structure.

	// Other unchanged fields omitted for brevity.
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

	// RuntimeHash is the cryptographic digest of the runtime binary.
	RuntimeHash hash.Hash `json:"runtime_hash"`
}
```

The intended workflow here is to:

- Deploy runtimes with the initial Deployment populated.

- Update the runtime version via the deployment of a new version
  of the descriptor with an additional version info entry.
  Sufficient nodes must upgrade their runtime binary and
  configuration by the `ValidFrom` epoch or the runtime will fail
  to be scheduled (no special handling is done, this is the existing
  "insufficient nodes" condition).

- Aborting or altering pending updates via the deployment of a new version
  of the descriptor with the removed/ammended not-yet-valid `Deployments`
  is possible in this design, but perhaps should be forbidden.

- Altering exisiting `Deployments` entries is strictly forbidden,
  except the removal of superceded descriptors.

- Deploying descriptors with `Deployments` that will never be valid
  (as in one that is superceded by a newer version) is strictly
  forbidden.

The `RuntimeHash` digest is to be used on each exeuctor node to catch
misconfiguration.  It will be enforced on a per-node basis, with an
optional (unsafe) way to disable verification, though with deterministic
builds, there is no reason in the common case why a mismatch should occur.

The existing node descriptor is a flat vector of `Runtime` entries
containing the runtime ID, version, and TEE information, so no changes
are required.

On transition to an epoch where a new version takes effect, the consensus
layer MAY prune the descriptor's `Deployments` field of superceded versions.

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
