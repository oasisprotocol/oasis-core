package byzantine

import (
	"context"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/worker/registration"
)

func registryRegisterNode(svc service.TendermintService, id *identity.Identity, dataDir string, addresses []node.Address, p2pAddresses []node.Address, runtimeID common.Namespace, capabilities *node.Capabilities, roles node.RolesMask) error {
	entityID, registrationSigner, err := registration.GetRegistrationSigner(logging.GetLogger("cmd/byzantine/registration"), dataDir, id)
	if err != nil {
		return errors.Wrap(err, "registration GetRegistrationSigner")
	}
	if registrationSigner == nil {
		return errors.New("nil registrationSigner")
	}

	var runtimes []*node.Runtime
	if roles&registry.RuntimesRequiredRoles != 0 {
		runtimes = []*node.Runtime{
			&node.Runtime{
				ID: runtimeID,
			},
		}
	}

	var committeeAddresses []node.CommitteeAddress
	for _, addr := range addresses {
		committeeAddresses = append(committeeAddresses, node.CommitteeAddress{
			Certificate: id.TLSCertificate.Certificate[0],
			Address:     addr,
		})
	}

	nodeDesc := &node.Node{
		ID:         id.NodeSigner.Public(),
		EntityID:   entityID,
		Expiration: 1000,
		Committee: node.CommitteeInfo{
			Certificate: id.TLSCertificate.Certificate[0],
			Addresses:   committeeAddresses,
		},
		P2P: node.P2PInfo{
			ID:        id.P2PSigner.Public(),
			Addresses: p2pAddresses,
		},
		Consensus: node.ConsensusInfo{
			ID: id.ConsensusSigner.Public(),
		},
		Runtimes: runtimes,
		Roles:    roles,
	}
	if capabilities != nil {
		nodeDesc.Runtimes[0].Capabilities = *capabilities
	}
	signedNode, err := node.MultiSignNode(
		[]signature.Signer{
			registrationSigner,
			id.P2PSigner,
			id.ConsensusSigner,
			id.TLSSigner,
		},
		registry.RegisterGenesisNodeSignatureContext,
		nodeDesc,
	)
	if err != nil {
		return errors.Wrap(err, "node SignNode")
	}

	tx := registry.NewRegisterNodeTx(0, nil, signedNode)
	if err := consensus.SignAndSubmitTx(context.Background(), svc, registrationSigner, tx); err != nil {
		return errors.Wrap(err, "consensus RegisterNode tx")
	}
	return nil
}

func registryGetNode(ht *honestTendermint, height int64, nodeID signature.PublicKey) (*node.Node, error) {
	return ht.service.Registry().GetNode(context.Background(), &registry.IDQuery{ID: nodeID, Height: height})
}
