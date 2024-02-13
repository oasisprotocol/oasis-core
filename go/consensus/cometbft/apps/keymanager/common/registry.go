package common

import (
	"fmt"
	"slices"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// KeyManagerRuntime looks up a runtime by its identifier and returns it
// if it exists and is a key manager.
func KeyManagerRuntime(ctx *tmapi.Context, rtID common.Namespace) (*registry.Runtime, error) {
	regState := registryState.NewMutableState(ctx.State())

	rt, err := regState.Runtime(ctx, rtID)
	if err != nil {
		return nil, err
	}
	if rt.Kind != registry.KindKeyManager {
		return nil, fmt.Errorf("keymanager: runtime is not a key manager: %s", rtID)
	}

	return rt, nil
}

// NodeRuntime searches for an existing supported runtime descriptor
// in the runtimes of the specified node and returns the first one found.
//
// This is a helper function for fetching the key manager runtime,
// as key managers run exactly one version of the runtime.
func NodeRuntime(n *node.Node, rtID common.Namespace) (*node.Runtime, error) {
	idx := slices.IndexFunc(n.Runtimes, func(rt *node.Runtime) bool {
		return rt.ID == rtID
	})
	if idx == -1 {
		return nil, fmt.Errorf("keymanager: node is not a key manager")
	}

	return n.Runtimes[idx], nil
}

// NodeRuntimes searches for existing supported runtime descriptors
// in the runtimes of the specified nodes.
//
// If a node doesn't support the runtime, it is ignored.
func NodeRuntimes(nodes []*node.Node, rtID common.Namespace) []*node.Runtime {
	nodeRts := make([]*node.Runtime, 0, len(nodes))
	for _, n := range nodes {
		nodeRt, err := NodeRuntime(n, rtID)
		if err != nil {
			continue
		}
		nodeRts = append(nodeRts, nodeRt)
	}

	return nodeRts
}

// RuntimeAttestationKey returns the runtime attestation key for the specified node runtime.
func RuntimeAttestationKey(nodeRt *node.Runtime, kmRt *registry.Runtime) (*signature.PublicKey, error) {
	// Registration ensures that node's hardware meets the TEE requirements
	// of the key manager runtime.
	switch kmRt.TEEHardware {
	case node.TEEHardwareInvalid:
		return &api.InsecureRAK, nil
	case node.TEEHardwareIntelSGX:
		if nodeRt.Capabilities.TEE == nil {
			return nil, fmt.Errorf("keymanager: node doesn't have TEE capability")
		}
		return &nodeRt.Capabilities.TEE.RAK, nil
	default:
		return nil, fmt.Errorf("keymanager: TEE hardware mismatch")
	}
}

// RuntimeEncryptionKeys returns the runtime encryption keys (REKs) for the specified node runtimes.
func RuntimeEncryptionKeys(nodeRts []*node.Runtime, kmRt *registry.Runtime) map[x25519.PublicKey]struct{} {
	reks := make(map[x25519.PublicKey]struct{})
	for _, nodeRt := range nodeRts {
		var rek x25519.PublicKey
		switch kmRt.TEEHardware {
		case node.TEEHardwareInvalid:
			rek = api.InsecureREK
		case node.TEEHardwareIntelSGX:
			if nodeRt.Capabilities.TEE == nil || nodeRt.Capabilities.TEE.REK == nil {
				continue
			}
			rek = *nodeRt.Capabilities.TEE.REK
		default:
			continue
		}

		reks[rek] = struct{}{}
	}

	return reks
}
