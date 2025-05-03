package byzantine

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

func registryRegisterNode(svc consensus.Service, id *identity.Identity, p2pAddresses []node.Address, runtimeID common.Namespace, capabilities *node.Capabilities, roles node.RolesMask) error {
	entityID, registrationSigner, err := registration.GetRegistrationSigner(id)
	if err != nil {
		return fmt.Errorf("registration GetRegistrationSigner: %w", err)
	}
	if registrationSigner == nil {
		return fmt.Errorf("nil registrationSigner")
	}

	var runtimes []*node.Runtime
	if roles&registry.RuntimesRequiredRoles != 0 {
		runtimes = []*node.Runtime{
			{
				ID: runtimeID,
			},
		}
	}

	nodeDesc := &node.Node{
		Versioned:  cbor.NewVersioned(node.LatestNodeDescriptorVersion),
		ID:         id.NodeSigner.Public(),
		EntityID:   entityID,
		Expiration: 1000,
		TLS: node.TLSInfo{
			PubKey: id.TLSSigner.Public(),
		},
		P2P: node.P2PInfo{
			ID:        id.P2PSigner.Public(),
			Addresses: p2pAddresses,
		},
		Consensus: node.ConsensusInfo{
			ID: id.ConsensusSigner.Public(),
		},
		VRF: node.VRFInfo{
			ID: id.VRFSigner.Public(),
		},
		Runtimes: runtimes,
		Roles:    roles,
	}
	if capabilities != nil {
		nodeDesc.Runtimes[0].Capabilities = *capabilities
	}
	if roles&node.RoleValidator != 0 {
		if nodeDesc.Consensus.Addresses, err = svc.GetAddresses(); err != nil {
			return fmt.Errorf("consensus GetAddresses: %w", err)
		}
	}
	signedNode, err := node.MultiSignNode(
		[]signature.Signer{
			registrationSigner,
			id.P2PSigner,
			id.ConsensusSigner,
			id.VRFSigner,
			id.TLSSigner,
		},
		registry.RegisterGenesisNodeSignatureContext,
		nodeDesc,
	)
	if err != nil {
		return fmt.Errorf("node SignNode: %w", err)
	}

	tx := registry.NewRegisterNodeTx(0, nil, signedNode)
	if err := consensus.SignAndSubmitTx(context.Background(), svc, registrationSigner, tx); err != nil {
		return fmt.Errorf("consensus RegisterNode tx: %w", err)
	}
	return nil
}
