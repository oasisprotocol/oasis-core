package committee

import (
	"github.com/oasisprotocol/oasis-core/go/common/node"
)

// RegisterNodeRuntime adds our runtime registration to an existing node descriptor.
func (n *Node) RegisterNodeRuntime(nd *node.Node) error {
	// Obtain the active runtime version.
	activeVersion, err := n.GetHostedRuntimeActiveVersion()
	if err != nil {
		n.logger.Warn("failed to get active runtime version, skipping",
			"err", err,
		)
		return nil
	}

	for _, version := range n.Runtime.HostVersions() {
		// Skip sending any old versions that will never be active again.
		if version.ToU64() < activeVersion.ToU64() {
			continue
		}

		// Obtain CapabilityTEE for the given runtime version.
		capabilityTEE, err := n.GetHostedRuntimeCapabilityTEEForVersion(version)
		if err != nil {
			n.logger.Warn("failed to get CapabilityTEE for hosted runtime, skipping",
				"err", err,
				"version", version,
			)
			continue
		}

		rt := nd.AddOrUpdateRuntime(n.Runtime.ID(), version)
		rt.Capabilities.TEE = capabilityTEE
	}
	return nil
}
