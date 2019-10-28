package byzantine

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	registryapp "github.com/oasislabs/oasis-core/go/tendermint/apps/registry"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
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

	if err := tendermintBroadcastTxCommit(svc, registryapp.TransactionTag, registryapp.Tx{
		TxRegisterNode: &registryapp.TxRegisterNode{
			Node: *signedNode,
		},
	}); err != nil {
		return errors.Wrap(err, "Tendermint BroadcastTx commit")
	}

	return nil
}

func registryGetNode(ht *honestTendermint, height int64, runtimeID signature.PublicKey) (*node.Node, error) {
	q, err := ht.registryQuery.QueryAt(height)
	if err != nil {
		return nil, err
	}

	return q.Node(context.Background(), runtimeID)
}
