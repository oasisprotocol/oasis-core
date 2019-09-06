package byzantine

import (
	"time"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
	registryapp "github.com/oasislabs/ekiden/go/tendermint/apps/registry"
	"github.com/oasislabs/ekiden/go/tendermint/service"
	"github.com/oasislabs/ekiden/go/worker/registration"
)

func registryRegisterNode(svc service.TendermintService, id *identity.Identity, dataDir string, committeeAddresses []node.Address, p2pInfo node.P2PInfo, runtimeID signature.PublicKey, roles node.RolesMask) error {
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
		P2P:              p2pInfo,
		RegistrationTime: uint64(time.Now().Unix()),
		Runtimes: []*node.Runtime{
			&node.Runtime{
				ID: runtimeID,
			},
		},
		Roles: roles,
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

func registryGetNode(svc service.TendermintService, height int64, runtimeID signature.PublicKey) (*node.Node, error) {
	response, err := svc.Query(registryapp.QueryGetNode, tmapi.QueryGetByIDRequest{
		ID: runtimeID,
	}, height)
	if err != nil {
		return nil, errors.Wrapf(err, "Tendermint Query %s", registryapp.QueryGetNode)
	}

	var node node.Node
	if err := cbor.Unmarshal(response, &node); err != nil {
		return nil, errors.Wrap(err, "CBOR Unmarshal node")
	}

	return &node, nil
}
