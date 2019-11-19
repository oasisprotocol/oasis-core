package byzantine

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/worker/registration"
)

func registryRegisterNode(svc service.TendermintService, id *identity.Identity, dataDir string, committeeAddresses []node.Address, p2pInfo node.P2PInfo, runtimeID signature.PublicKey, capabilities *node.Capabilities, roles node.RolesMask) error {
	entityID, registrationSigner, err := registration.GetRegistrationSigner(logging.GetLogger("cmd/byzantine/registration"), dataDir, id)
	if err != nil {
		return errors.Wrap(err, "registration GetRegistrationSigner")
	}
	if registrationSigner == nil {
		return errors.New("nil registrationSigner")
	}

	nodeDesc := &node.Node{
		ID:         id.NodeSigner.Public(),
		EntityID:   entityID,
		Expiration: 1000,
		Committee: node.CommitteeInfo{
			Certificate: id.TLSCertificate.Certificate[0],
			Addresses:   committeeAddresses,
		},
		P2P: p2pInfo,
		Consensus: node.ConsensusInfo{
			ID: id.ConsensusSigner.Public(),
		},
		RegistrationTime: uint64(time.Now().Unix()),
		Runtimes: []*node.Runtime{
			&node.Runtime{
				ID: runtimeID,
			},
		},
		Roles: roles,
	}
	if capabilities != nil {
		nodeDesc.Runtimes[0].Capabilities = *capabilities
	}
	signedNode, err := node.SignNode(registrationSigner, registry.RegisterGenesisNodeSignatureContext, nodeDesc)
	if err != nil {
		return errors.Wrap(err, "node SignNode")
	}

	tx := registry.NewRegisterNodeTx(0, nil, signedNode)
	if err := consensus.SignAndSubmitTx(context.Background(), svc, id.NodeSigner, tx); err != nil {
		return errors.Wrap(err, "consensus RegisterNode tx")
	}
	return nil
}

func registryGetNode(ht *honestTendermint, height int64, nodeID signature.PublicKey) (*node.Node, error) {
	return ht.service.Registry().GetNode(context.Background(), nodeID, height)
}
